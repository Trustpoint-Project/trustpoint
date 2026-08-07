# Certificate Authorities, Registration Authorities, and Keyless CAs

Trustpoint uses Certificate Authorities (CAs) and Registration Authorities (RAs) to issue and manage certificates for domains, devices, and services.

## Certificate Authority (CA)

A Certificate Authority signs certificates. In Trustpoint, an **Issuing CA** owns or has access to the private key that is used to issue certificates.

Use an Issuing CA when Trustpoint should issue certificates directly, for example for devices, domain credentials, TLS certificates, or OPC UA certificates.

An Issuing CA can be:

- imported from an existing key and certificate,
- imported from a PKCS#12 file,
- requested from an upstream CA using EST,
- requested from an upstream CA using CMP.

## Registration Authority (RA)

A Registration Authority validates certificate requests but does not sign certificates itself. The actual certificate is issued by a remote CA.

Use an RA setup when Trustpoint should act as the local enrollment and policy component while certificate signing remains with an external PKI.

This is useful when an organization already operates a central CA and Trustpoint should integrate into it instead of becoming a standalone issuing CA.

## Keyless CA

A keyless CA represents a CA certificate in Trustpoint without the corresponding private key. Trustpoint can use it to display CA information, manage trust relationships, and store CRLs, but it cannot issue certificates for this CA.

Use a keyless CA when Trustpoint needs to know or trust a CA, but the private key is managed elsewhere.

For keyless CAs, users can upload CRLs manually because Trustpoint cannot generate CRLs without the CA private key.

## Summary

| Concept | Has private key in Trustpoint | Issues certificates | Typical use |
|---|---:|---:|---|
| Issuing CA | Yes | Yes | Trustpoint issues certificates directly |
| RA | No | No | Trustpoint forwards approved requests to a remote CA |
| Keyless CA | No | No | Trustpoint stores CA and CRL information only |