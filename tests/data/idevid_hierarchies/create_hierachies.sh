#!/usr/bin/env bash

# ============================================================
# Config
# ============================================================
ROOT_CN="Trustpoint Demo IDevID Hierarchy - Root CA"
ISSUING_CN="Trustpoint Demo IDevID Hierarchy - Issuing CA"
PROFILE="ecc3"
curve=ec_paramgen_curve:secp521r1

# Issuing CA validity
ISSUING_NOT_BEFORE="20250216170500Z"  # Feb 16 17:05:00 2025 GMT
ISSUING_NOT_AFTER="20280217170500Z"   # Feb 17 17:05:00 2028 GMT

# End-entity cert validity
EE_DAYS=825

# Output dirs
mkdir -p "$PROFILE"

# ============================================================
# 1) Root CA
# ============================================================
echo "[*] Generating Root CA key"
openssl genpkey \
  -algorithm EC \
  -pkeyopt "$curve" \
  -pkeyopt ec_param_enc:named_curve \
  -out "$PROFILE/root-ca.key"

cat > "$PROFILE/root-ca.ext" <<'EOF'
[v3_ca]
basicConstraints=critical,CA:true,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

openssl req -new -sha256 \
  -key "$PROFILE/root-ca.key" \
  -subj "/CN=Trustpoint Demo IDevID Hierarchy - Root CA/UID=$PROFILE" \
  -out "$PROFILE/root-ca.csr"

echo "[*] Self-signing Root CA certificate (ECDSA with SHA-256)…"
openssl x509 -req -sha256 -days 3650 \
  -in "$PROFILE/root-ca.csr" \
  -signkey "$PROFILE/root-ca.key" \
  -extensions v3_ca -extfile "$PROFILE/root-ca.ext" \
  -out "$PROFILE/root-ca.crt"

# ============================================================
# 2) Issuing CA signed by Root
# ============================================================
echo "[*] Generating Issuing CA key"
openssl genpkey \
  -algorithm EC \
  -pkeyopt "$curve" \
  -pkeyopt ec_param_enc:named_curve \
  -out "$PROFILE/issuing-ca.key"

echo "[*] Creating Issuing CA CSR…"
openssl req -new -sha256 \
  -key "$PROFILE/issuing-ca.key" \
  -subj "/CN=${ISSUING_CN}/UID=${PROFILE}" \
  -out "$PROFILE/issuing-ca.csr"

cat > "$PROFILE/issuing-ca.ext" <<'EOF'
[v3_ica]
basicConstraints=critical,CA:true,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
EOF

echo "[*] Signing Issuing CA with Root…"
openssl x509 -req -sha256 -days 1095 \
  -in "$PROFILE/issuing-ca.csr" \
  -CA "$PROFILE/root-ca.crt" -CAkey "$PROFILE/root-ca.key" \
  -CAcreateserial \
  -extensions v3_ica -extfile "$PROFILE/issuing-ca.ext" \
  -out "$PROFILE/issuing-ca.crt"

# ============================================================
# 3) End-entity credentials from Issuing CA
# ============================================================
cat > "$PROFILE/ee.ext" <<'EOF'
[v3_leaf]
basicConstraints=critical,CA:false
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth,serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

# --- Credential A (serial 123) ---
echo "[*] Generating Credential A key"
openssl genpkey \
  -algorithm EC \
  -pkeyopt "$curve" \
  -pkeyopt ec_param_enc:named_curve \
  -out "$PROFILE/cred-123.key"

echo "[*] Creating Credential A CSR (no enrollment code)…"
openssl req -new -sha256 \
  -key "$PROFILE/cred-123.key" \
  -subj "/CN=Credential 123/serialNumber=123" \
  -out "$PROFILE/cred-123.csr"

echo "[*] Signing Credential A with Issuing CA (serial 123)…"
openssl x509 -req -sha256 -days "${EE_DAYS}" \
  -in "$PROFILE/cred-123.csr" \
  -CA "$PROFILE/issuing-ca.crt" -CAkey "$PROFILE/issuing-ca.key" \
  -set_serial 123 \
  -extensions v3_leaf -extfile "$PROFILE/ee.ext" \
  -out "$PROFILE/cred-123.crt"

# --- Credential B (serial 321) ---
echo "[*] Generating Credential B key"
openssl genpkey \
  -algorithm EC \
  -pkeyopt "$curve" \
  -pkeyopt ec_param_enc:named_curve \
  -out "$PROFILE/cred-321.key"

echo "[*] Creating Credential B CSR (no enrollment code)…"
openssl req -new -sha256 \
  -key "$PROFILE/cred-321.key" \
  -subj "/CN=Credential 321/serialNumber=321" \
  -out "$PROFILE/cred-321.csr"

echo "[*] Signing Credential B with Issuing CA (serial 321)…"
openssl x509 -req -sha256 -days "${EE_DAYS}" \
  -in "$PROFILE/cred-321.csr" \
  -CA "$PROFILE/issuing-ca.crt" -CAkey "$PROFILE/issuing-ca.key" \
  -set_serial 321 \
  -extensions v3_leaf -extfile "$PROFILE/ee.ext" \
  -out "$PROFILE/cred-321.crt"

# ============================================================
# 4) Build chains and cleanup
# ============================================================

cat "$PROFILE/issuing-ca.crt" "$PROFILE/root-ca.crt" > "$PROFILE/${PROFILE}_chain.pem"

echo "[*] Creating PKCS#12 bundles (no password)…"

openssl pkcs12 -export \
  -inkey "$PROFILE/cred-123.key" \
  -in "$PROFILE/cred-123.crt" \
  -certfile "$PROFILE/${PROFILE}_chain.pem" \
  -out "$PROFILE/${PROFILE}_123.p12" \
  -passout pass:

openssl pkcs12 -export \
  -inkey "$PROFILE/cred-321.key" \
  -in "$PROFILE/cred-321.crt" \
  -certfile "$PROFILE/${PROFILE}_chain.pem" \
  -out "$PROFILE/${PROFILE}_321.p12" \
  -passout pass:

cd "$PROFILE"

# keep only ecc2_123.p12, ecc2_321.p12, ecc2_chain.pem
find . -maxdepth 1 -type f ! -name "${PROFILE}_123.p12" ! -name "${PROFILE}_321.p12" ! -name "${PROFILE}_chain.pem" -delete

