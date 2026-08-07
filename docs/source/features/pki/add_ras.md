# Add a Remote RA

A Remote RA setup allows Trustpoint to validate and forward certificate requests to an external CA. Trustpoint does not sign the certificates itself.

Use this option when certificate issuance should stay with an existing PKI, but Trustpoint should provide local enrollment handling, policy checks, and domain integration.

## Access

Go to **PKI > Certificate Authorities > Add new Issuing CA > Select method**.

## Available methods

### Configure a Remote Issuing CA using EST

Configure Trustpoint to forward approved certificate requests to a remote CA using EST.

Use this when the upstream CA provides an EST endpoint.

### Configure a Remote Issuing CA using CMP

Configure Trustpoint to forward approved certificate requests to a remote CA using CMP.

Use this when the upstream CA provides a CMP endpoint.

## Result

After the remote CA connection has been configured, Trustpoint can use it as the issuing backend for domains while keeping the CA private key outside Trustpoint.