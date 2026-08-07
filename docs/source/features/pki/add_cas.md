# Add an Issuing CA

An Issuing CA signs certificates. Use this option when Trustpoint should issue certificates directly.

## Access

Go to **PKI > Certificate Authorities > Add new Issuing CA > Select method**.

## Available methods

### Import from PKCS#12 file

Import an existing CA certificate together with its private key from a PKCS#12 file.

Use this when the Issuing CA already exists and should be managed by Trustpoint.

### Import from separate key and certificate files

Import an existing CA using separate private key and certificate files.

Use this when the key and certificate are stored as individual files instead of a PKCS#12 container.

### Request Issuing CA certificate using EST

Generate a new key pair in Trustpoint and request an Issuing CA certificate from an upstream CA using EST.

Use this when Trustpoint should become a subordinate CA under an existing EST-based PKI.

### Request Issuing CA certificate using CMP

Generate a new key pair in Trustpoint and request an Issuing CA certificate from an upstream CA using CMP.

Use this when Trustpoint should become a subordinate CA under an existing CMP-based PKI.

## Result

After the Issuing CA has been added, it can be assigned to a domain and used to issue certificates according to the enabled certificate profiles.