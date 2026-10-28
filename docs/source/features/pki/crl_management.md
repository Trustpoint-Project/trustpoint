# CRL Management

Trustpoint manages Certificate Revocation Lists (CRLs) per CA.

## Access

Go to **PKI > Certificate Authorities**, select an **Issuing CA**, then open **Configure**.

## Actions

- **Generate CRL**: create a new CRL.
- **CRL Details**: view metadata of the latest CRL.
- **Download CRL**: download the CRL file.
- **Download CRL with curl**: show a direct download command.

## Configuration

- **Enable CRL Cycle Updates**: generate CRLs periodically.
- **CRL Cycle Interval**: time between CRL generations.
- **CRL Validity**: validity period of generated CRLs.
- **Auto-Generate CRL on Revocation**: create a new CRL after certificate revocation.

Use **Save CRL Settings** to apply changes.

## CRL Distribution Points in Certificate Profiles

Certificate profiles configure the URLs included in an issued certificate's
**CRL Distribution Points** extension. Under **PKI > Certificate Profiles**, use
**CRL Dist Points → URIs** in the profile builder to define a fixed URL or a
template, for example:

```text
http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}
```

`{tls_certificate.ip_address.1}` uses the first IP SAN of the active Trustpoint
TLS certificate. `{issuing_ca.id}` uses the issuing CA's database ID. A fixed
host is also supported, such as `http://2.2.2.2/crl/{issuing_ca.id}`. Use HTTP
for Trustpoint-hosted CRLs and include a port if the endpoint uses a
nonstandard HTTP port.

The URL identifies the CA's active CRL, so it remains unchanged when a new CRL
is published. The CA ID in the URL is independent of the CRL's changing sequence
number. Configure CRL generation and validity above to keep the published CRL
current.

Trustpoint also accepts `/crl/<CA ID>.crl`, for example `/crl/4.crl`,
as an alias for `/crl/4/`. Both URLs serve the same active CRL and support the
same encoding options. The `.crl` suffix requires no additional profile setting.

The manual issuance form displays resolved URLs. Enable **Mutable** in the
profile to allow users to edit them for an individual issuance. Profile changes
affect future certificates; existing certificates retain their original URLs.

See [Certificate Profiles — CRL Distribution Points](certificate_profiles.md#crl-distribution-points)
for JSON configuration examples, placeholder rules, and validation details.

## Keyless CAs

For non-issuing CAs, Trustpoint cannot generate CRLs. The user can upload an externally generated CRL instead.