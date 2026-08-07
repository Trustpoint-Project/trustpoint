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

## Keyless CAs

For non-issuing CAs, Trustpoint cannot generate CRLs. The user can upload an externally generated CRL instead.