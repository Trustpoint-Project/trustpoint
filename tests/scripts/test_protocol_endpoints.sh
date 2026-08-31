#!/usr/bin/env bash
# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT
#
# Integration test for the CMP, EST and REST certificate issuance endpoints.
#
# Expects a running Trustpoint HTTPS server and a test environment created with
#   uv run trustpoint/manage.py create_protocol_test_env --output <env-file>
#
# Each protocol uses its own issuing CA, domain and signature algorithm, because Trustpoint
# requires the end entity key to match the signature suite of the issuing CA:
#
#   EST  -> EC P-256
#   CMP  -> ML-DSA-65   (requires OpenSSL >= 3.5)
#   REST -> RSA-2048
#
# For every protocol two devices are exercised:
#   * a device without onboarding, authenticating directly with its shared secret
#   * a device with onboarding, which first obtains a domain credential and then
#     uses that credential to request the application certificate
#
# In each case a TLS server certificate (profile "tls_server") is requested.

set -euo pipefail

HOST="127.0.0.1:443"
ENV_FILE=""
TLS_CERT=""
WORK_DIR=""

usage() {
    cat <<'EOF'
Usage: test_protocol_endpoints.sh --env-file <json> --tls-cert <pem> [--host <host:port>] [--work-dir <dir>]

  --env-file   JSON file written by the create_protocol_test_env management command.
  --tls-cert   PEM file used as curl/openssl trust anchor for the Trustpoint HTTPS server.
  --host       Host and port of the Trustpoint server (default: 127.0.0.1:443).
  --work-dir   Directory for generated keys and certificates (default: a temporary directory).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --host) HOST="$2"; shift 2 ;;
        --env-file) ENV_FILE="$2"; shift 2 ;;
        --tls-cert) TLS_CERT="$2"; shift 2 ;;
        --work-dir) WORK_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "${ENV_FILE}" || -z "${TLS_CERT}" ]]; then
    usage >&2
    exit 2
fi

for tool in openssl curl jq python3; do
    command -v "${tool}" >/dev/null || { echo "Required tool not found: ${tool}" >&2; exit 2; }
done

if ! openssl genpkey -algorithm ML-DSA-65 -out /dev/null 2>/dev/null; then
    echo "ML-DSA is not supported by $(openssl version). OpenSSL >= 3.5 is required." >&2
    exit 2
fi

TLS_CERT="$(cd "$(dirname "${TLS_CERT}")" && pwd)/$(basename "${TLS_CERT}")"
ENV_FILE="$(cd "$(dirname "${ENV_FILE}")" && pwd)/$(basename "${ENV_FILE}")"

if [[ -z "${WORK_DIR}" ]]; then
    WORK_DIR="$(mktemp -d)"
fi
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}"

BASE_URL="https://${HOST}"
APP_PROFILE="tls_server"

APP_SUBJECT="/CN=tls_server.local"
APP_SAN_REQ="critical, DNS:localhost, IP:127.0.0.1, IP:::1"
APP_SAN_CMP="localhost 127.0.0.1 ::1"
DC_SUBJECT="/CN=Trustpoint-Domain-Credential"

FAILURES=0

proto_field() {
    jq -r ".protocols[\"$1\"].$2" "${ENV_FILE}"
}

device_field() {
    jq -r ".protocols[\"$1\"].devices[\"$2\"].$3" "${ENV_FILE}"
}

log() {
    echo
    echo "=== $* ==="
}

fail() {
    echo "FAIL: $*" >&2
    FAILURES=$((FAILURES + 1))
    return 1
}

gen_key() {
    local out="$1" algorithm="$2"
    case "${algorithm}" in
        rsa) openssl genrsa -out "${out}" 2048 2>/dev/null ;;
        ec) openssl ecparam -name prime256v1 -genkey -noout -out "${out}" ;;
        mldsa) openssl genpkey -algorithm ML-DSA-65 -out "${out}" 2>/dev/null ;;
        *) fail "Unsupported key algorithm: ${algorithm}"; return 1 ;;
    esac || { fail "Could not generate ${algorithm} key ${out}"; return 1; }
}

# Maps the environment key algorithm to the name OpenSSL prints for the public key.
expected_public_key_algorithm() {
    case "$1" in
        rsa) echo 'rsaEncryption' ;;
        ec) echo 'id-ecPublicKey' ;;
        mldsa) echo 'ML-DSA-65' ;;
        *) echo 'unknown' ;;
    esac
}

gen_app_csr_der() {
    openssl req -new -key "$1" -outform DER -out "$2" \
        -addext "subjectAltName = ${APP_SAN_REQ}" -subj "${APP_SUBJECT}" \
        || { fail "Could not create CSR $2"; return 1; }
}

gen_app_csr_pem() {
    openssl req -new -key "$1" -out "$2" \
        -addext "subjectAltName = ${APP_SAN_REQ}" -subj "${APP_SUBJECT}" \
        || { fail "Could not create CSR $2"; return 1; }
}

gen_dc_csr() {
    local key="$1" out="$2"
    shift 2
    openssl req -new -key "${key}" -out "${out}" -subj "${DC_SUBJECT}" "$@" \
        || { fail "Could not create domain credential CSR ${out}"; return 1; }
}

# Extracts the certificate with the given subject common name from a PEM bundle.
extract_cert_by_cn() {
    local bundle="$1" cn="$2" out="$3" dir count i subject
    dir="$(mktemp -d)"
    awk -v dir="${dir}" '/-----BEGIN CERTIFICATE-----/{n++} n>0{print > (dir "/cert-" n ".pem")}' "${bundle}"
    count="$(find "${dir}" -name 'cert-*.pem' | wc -l | tr -d ' ')"
    for ((i = 1; i <= count; i++)); do
        subject="$(openssl x509 -in "${dir}/cert-${i}.pem" -noout -subject 2>/dev/null || true)"
        if [[ "${subject}" == *"CN = ${cn}"* || "${subject}" == *"CN=${cn}"* ]]; then
            cp "${dir}/cert-${i}.pem" "${out}"
            rm -rf "${dir}"
            return 0
        fi
    done
    rm -rf "${dir}"
    echo "No certificate with CN='${cn}' found in ${bundle}" >&2
    return 1
}

# Decodes a base64 encoded PKCS#7 EST response into a PEM bundle, rejecting error bodies
# that were returned with a 2xx status.
decode_pkcs7_response() {
    local response="$1" bundle="$2" label="$3"
    if [[ ! -s "${response}" ]]; then
        fail "${label}: empty response body"
        return 1
    fi
    if ! base64 -d -i "${response}" 2>/dev/null | openssl pkcs7 -inform DER -print_certs -out "${bundle}" 2>/dev/null; then
        fail "${label}: response is not a base64 encoded PKCS#7 structure: $(head -c 200 "${response}")"
        return 1
    fi
    return 0
}

# Extracts the "certificate" member of a REST response, rejecting error payloads.
extract_rest_certificate() {
    local response="$1" cert="$2" label="$3" value
    if ! value="$(jq -er .certificate "${response}" 2>/dev/null)"; then
        fail "${label}: response contains no certificate: $(head -c 200 "${response}")"
        return 1
    fi
    printf '%s\n' "${value}" > "${cert}"
    return 0
}

assert_tls_server_cert() {
    local cert="$1" label="$2" ca_name="$3" algorithm="$4" subject issuer expected_algorithm

    if [[ ! -s "${cert}" ]]; then
        fail "${label}: no certificate was written"
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout >/dev/null 2>&1; then
        fail "${label}: response is not an X.509 certificate: $(head -c 200 "${cert}")"
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout -checkend 0 >/dev/null 2>&1; then
        fail "${label}: certificate is already expired"
        return 1
    fi

    subject="$(openssl x509 -in "${cert}" -noout -subject)"
    issuer="$(openssl x509 -in "${cert}" -noout -issuer)"
    expected_algorithm="$(expected_public_key_algorithm "${algorithm}")"

    if [[ "${subject}" != *'tls_server.local'* ]]; then
        fail "${label}: unexpected subject: ${subject}"
        return 1
    fi
    if [[ "${issuer}" != *"${ca_name}"* ]]; then
        fail "${label}: unexpected issuer: ${issuer}"
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout -text | grep -q "Public Key Algorithm: ${expected_algorithm}"; then
        fail "${label}: expected a ${expected_algorithm} key, got: $(
            openssl x509 -in "${cert}" -noout -text | grep -m1 'Public Key Algorithm:'
        )"
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout -ext extendedKeyUsage 2>/dev/null | grep -q 'TLS Web Server Authentication'; then
        fail "${label}: missing serverAuth extended key usage"
        return 1
    fi
    if ! openssl x509 -in "${cert}" -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:localhost'; then
        fail "${label}: missing subject alternative name"
        return 1
    fi

    echo "PASS: ${label}: ${subject} [${expected_algorithm}]"
    return 0
}

# Sends the domain credential as URL-encoded SSL-CLIENT-CERT header. On the development
# server there is no nginx in front of Trustpoint that would inject this header itself.
client_cert_header() {
    python3 -c "import sys, urllib.parse; print(urllib.parse.quote(open(sys.argv[1]).read()))" "$1"
}

curl_est() {
    local out="$1" url="$2"
    shift 2
    curl --silent --show-error --fail-with-body \
        --cacert "${TLS_CERT}" \
        --header 'Content-Type: application/pkcs10' \
        --output "${out}" \
        "$@" \
        "${url}"
}

curl_rest() {
    local out="$1" csr="$2" url="$3"
    shift 3
    curl --silent --show-error --fail-with-body \
        --cacert "${TLS_CERT}" \
        --header 'Content-Type: application/json' \
        --data-binary "$(jq -n --arg csr "$(cat "${csr}")" '{csr: $csr}')" \
        --output "${out}" \
        "$@" \
        "${url}"
}

# --------------------------------------------------------------------------------------
# EST
# --------------------------------------------------------------------------------------

test_est_no_onboarding() {
    local device='est-no-onboarding-device' p='est-no'
    local domain ca algorithm
    domain="$(proto_field est domain)"
    ca="$(proto_field est ca)"
    algorithm="$(proto_field est key_algorithm)"

    log "EST without onboarding (${device}, ${algorithm})"

    gen_key "${p}-key.pem" "${algorithm}" || return 1
    gen_app_csr_der "${p}-key.pem" "${p}-csr.der" || return 1

    curl_est "${p}.p7c" "${BASE_URL}/.well-known/est/${domain}/${APP_PROFILE}/simpleenroll" \
        --user "${device}:$(device_field est "${device}" est_password)" \
        --data-binary "@${p}-csr.der" || { fail "EST enrollment for ${device}: $(head -c 200 "${p}.p7c")"; return 1; }

    decode_pkcs7_response "${p}.p7c" "${p}-bundle.pem" 'EST / no onboarding' || return 1
    extract_cert_by_cn "${p}-bundle.pem" 'tls_server.local' "${p}-cert.pem" || { fail "${device}"; return 1; }
    assert_tls_server_cert "${p}-cert.pem" 'EST / no onboarding' "${ca}" "${algorithm}"
}

test_est_onboarding() {
    local device='est-onboarding-device' p='est-ob'
    local domain ca algorithm dc_profile password
    domain="$(proto_field est domain)"
    ca="$(proto_field est ca)"
    algorithm="$(proto_field est key_algorithm)"
    dc_profile="$(proto_field est domain_credential_profile)"
    password="$(device_field est "${device}" est_password)"

    log "EST with onboarding (${device}, ${algorithm})"

    gen_key "${p}-dc-key.pem" "${algorithm}" || return 1
    gen_dc_csr "${p}-dc-key.pem" "${p}-dc-csr.der" -outform DER || return 1

    curl_est "${p}-dc.p7c" "${BASE_URL}/.well-known/est/${domain}/${dc_profile}/simpleenroll" \
        --user "${device}:${password}" \
        --data-binary "@${p}-dc-csr.der" \
        || { fail "EST onboarding for ${device}: $(head -c 200 "${p}-dc.p7c")"; return 1; }

    decode_pkcs7_response "${p}-dc.p7c" "${p}-dc-bundle.pem" 'EST / onboarding' || return 1
    extract_cert_by_cn "${p}-dc-bundle.pem" 'Trustpoint-Domain-Credential' "${p}-dc-cert.pem" \
        || { fail "domain credential for ${device}"; return 1; }
    echo "Onboarded ${device}: $(openssl x509 -in "${p}-dc-cert.pem" -noout -subject)"

    gen_key "${p}-key.pem" "${algorithm}" || return 1
    gen_app_csr_der "${p}-key.pem" "${p}-csr.der" || return 1

    curl_est "${p}.p7c" "${BASE_URL}/.well-known/est/${domain}/${APP_PROFILE}/simpleenroll" \
        --cert "${p}-dc-cert.pem" --key "${p}-dc-key.pem" \
        --header "SSL-CLIENT-CERT: $(client_cert_header "${p}-dc-cert.pem")" \
        --data-binary "@${p}-csr.der" || { fail "EST enrollment for ${device}: $(head -c 200 "${p}.p7c")"; return 1; }

    decode_pkcs7_response "${p}.p7c" "${p}-bundle.pem" 'EST / onboarded' || return 1
    extract_cert_by_cn "${p}-bundle.pem" 'tls_server.local' "${p}-cert.pem" || { fail "${device}"; return 1; }
    assert_tls_server_cert "${p}-cert.pem" 'EST / onboarded' "${ca}" "${algorithm}"
}

# --------------------------------------------------------------------------------------
# CMP
# --------------------------------------------------------------------------------------

test_cmp_no_onboarding() {
    local device='cmp-no-onboarding-device' p='cmp-no'
    local domain ca algorithm
    domain="$(proto_field cmp domain)"
    ca="$(proto_field cmp ca)"
    algorithm="$(proto_field cmp key_algorithm)"

    log "CMP without onboarding (${device}, ${algorithm})"

    gen_key "${p}-key.pem" "${algorithm}" || return 1

    if ! openssl cmp -cmd cr \
        -tls_used -tls_trusted "${TLS_CERT}" \
        -server "${BASE_URL}/.well-known/cmp/p/${domain}/${APP_PROFILE}/certification" \
        -ref "$(device_field cmp "${device}" pk)" \
        -secret "pass:$(device_field cmp "${device}" cmp_shared_secret)" \
        -subject "${APP_SUBJECT}" -days 10 -sans "${APP_SAN_CMP}" \
        -newkey "${p}-key.pem" \
        -certout "${p}-cert.pem" -chainout "${p}-chain.pem" -extracertsout "${p}-full-chain.pem"; then
        fail "CMP enrollment for ${device}"
        return 1
    fi
    assert_tls_server_cert "${p}-cert.pem" 'CMP / no onboarding' "${ca}" "${algorithm}"
}

test_cmp_onboarding() {
    local device='cmp-onboarding-device' p='cmp-ob'
    local domain ca algorithm dc_profile pk secret
    domain="$(proto_field cmp domain)"
    ca="$(proto_field cmp ca)"
    algorithm="$(proto_field cmp key_algorithm)"
    dc_profile="$(proto_field cmp domain_credential_profile)"
    pk="$(device_field cmp "${device}" pk)"
    secret="$(device_field cmp "${device}" cmp_shared_secret)"

    log "CMP with onboarding (${device}, ${algorithm})"

    gen_key "${p}-dc-key.pem" "${algorithm}" || return 1

    if ! openssl cmp -cmd ir \
        -tls_used -tls_trusted "${TLS_CERT}" \
        -server "${BASE_URL}/.well-known/cmp/p/${domain}/${dc_profile}/initialization" \
        -ref "${pk}" -secret "pass:${secret}" \
        -subject "${DC_SUBJECT}" \
        -newkey "${p}-dc-key.pem" \
        -certout "${p}-dc-cert.pem" -chainout "${p}-dc-chain.pem" -extracertsout "${p}-dc-full-chain.pem"; then
        fail "CMP onboarding for ${device}"
        return 1
    fi
    echo "Onboarded ${device}: $(openssl x509 -in "${p}-dc-cert.pem" -noout -subject)"

    gen_key "${p}-key.pem" "${algorithm}" || return 1

    if ! openssl cmp -cmd cr \
        -tls_used -tls_trusted "${TLS_CERT}" \
        -trusted "${p}-dc-full-chain.pem" \
        -server "${BASE_URL}/.well-known/cmp/p/${domain}/${APP_PROFILE}/certification" \
        -cert "${p}-dc-cert.pem" -key "${p}-dc-key.pem" \
        -subject "${APP_SUBJECT}" -days 10 -sans "${APP_SAN_CMP}" \
        -newkey "${p}-key.pem" \
        -certout "${p}-cert.pem" -chainout "${p}-chain.pem" -extracertsout "${p}-full-chain.pem"; then
        fail "CMP enrollment for ${device}"
        return 1
    fi
    assert_tls_server_cert "${p}-cert.pem" 'CMP / onboarded' "${ca}" "${algorithm}"
}

# --------------------------------------------------------------------------------------
# REST
# --------------------------------------------------------------------------------------

test_rest_no_onboarding() {
    local device='rest-no-onboarding-device' p='rest-no'
    local domain ca algorithm
    domain="$(proto_field rest domain)"
    ca="$(proto_field rest ca)"
    algorithm="$(proto_field rest key_algorithm)"

    log "REST without onboarding (${device}, ${algorithm})"

    gen_key "${p}-key.pem" "${algorithm}" || return 1
    gen_app_csr_pem "${p}-key.pem" "${p}-csr.pem" || return 1

    curl_rest "${p}.json" "${p}-csr.pem" "${BASE_URL}/rest/${domain}/${APP_PROFILE}/enroll/" \
        --user "${device}:$(device_field rest "${device}" est_password)" \
        || { fail "REST enrollment for ${device}: $(head -c 200 "${p}.json")"; return 1; }

    extract_rest_certificate "${p}.json" "${p}-cert.pem" 'REST / no onboarding' || return 1
    assert_tls_server_cert "${p}-cert.pem" 'REST / no onboarding' "${ca}" "${algorithm}"
}

test_rest_onboarding() {
    local device='rest-onboarding-device' p='rest-ob'
    local domain ca algorithm dc_profile password
    domain="$(proto_field rest domain)"
    ca="$(proto_field rest ca)"
    algorithm="$(proto_field rest key_algorithm)"
    dc_profile="$(proto_field rest domain_credential_profile)"
    password="$(device_field rest "${device}" est_password)"

    log "REST with onboarding (${device}, ${algorithm})"

    gen_key "${p}-dc-key.pem" "${algorithm}" || return 1
    gen_dc_csr "${p}-dc-key.pem" "${p}-dc-csr.pem" || return 1

    curl_rest "${p}-dc.json" "${p}-dc-csr.pem" "${BASE_URL}/rest/${domain}/${dc_profile}/enroll/" \
        --user "${device}:${password}" \
        || { fail "REST onboarding for ${device}: $(head -c 200 "${p}-dc.json")"; return 1; }

    extract_rest_certificate "${p}-dc.json" "${p}-dc-cert.pem" 'REST / onboarding' || return 1
    echo "Onboarded ${device}: $(openssl x509 -in "${p}-dc-cert.pem" -noout -subject)"

    gen_key "${p}-key.pem" "${algorithm}" || return 1
    gen_app_csr_pem "${p}-key.pem" "${p}-csr.pem" || return 1

    curl_rest "${p}.json" "${p}-csr.pem" "${BASE_URL}/rest/${domain}/${APP_PROFILE}/enroll/" \
        --cert "${p}-dc-cert.pem" --key "${p}-dc-key.pem" \
        --header "SSL-CLIENT-CERT: $(client_cert_header "${p}-dc-cert.pem")" \
        || { fail "REST enrollment for ${device}: $(head -c 200 "${p}.json")"; return 1; }

    extract_rest_certificate "${p}.json" "${p}-cert.pem" 'REST / onboarded' || return 1
    assert_tls_server_cert "${p}-cert.pem" 'REST / onboarded' "${ca}" "${algorithm}"
}

echo "Testing Trustpoint enrollment endpoints at ${BASE_URL}"
echo "Using $(openssl version)"
echo "Working directory: ${WORK_DIR}"

# Every test is allowed to fail so that all protocols are exercised in a single run.
test_est_no_onboarding || true
test_est_onboarding || true
test_cmp_no_onboarding || true
test_cmp_onboarding || true
test_rest_no_onboarding || true
test_rest_onboarding || true

echo
if [[ "${FAILURES}" -gt 0 ]]; then
    echo "${FAILURES} enrollment test(s) failed."
    exit 1
fi
echo 'All enrollment tests passed.'
