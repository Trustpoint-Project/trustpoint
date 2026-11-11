# User Authentication

Trustpoint supports multiple authentication methods for human users:

- **Password authentication**, with optional **one-time password (OTP)** verification
- **Certificate-based authentication** using TLS client certificates

If certificate authentication is enabled, users can use either an associated client certificate or the password-based login flow.

## Password + OTP

Password authentication remains enabled by default.

Administrators can configure the global password policy under **User Authentication → Password + OTP**. The policy includes settings such as:

- minimum password length
- password reuse prevention
- password expiry
- similarity checks
- common-password validation
- numeric-password validation
- optional OTP requirement

### OTP

OTP can be required globally for password-based logins.

When OTP is enabled:

1. The user enters their username and password.
2. If no authenticator is configured yet, Trustpoint guides the user through enrollment using a QR code.
3. The user verifies the login with a code from their authenticator application.
4. Existing users can also use an unused recovery code.

OTP applies to the **password login flow**. Certificate-based authentication is handled separately.

Human users requesting management API tokens must also provide an `otp` string
when OTP is required. They must first enroll an authenticator through the web UI.
The API accepts authenticator codes and unused recovery codes. Service-account
client credentials and refresh-token requests do not require OTP. Enabling OTP
does not invalidate existing tokens.

## Certificate-Based Authentication

Trustpoint can authenticate users with TLS client certificates.

Certificate authentication must first be configured and enabled by an administrator under:

**Management → User Authentication → Certificate**

A management CA signs the user authentication certificates. Select an existing
management CA on that page, or add a new one with the **Management CA** role.

### User Certificates

After certificate authentication has been enabled, users can manage their certificates from their profile.

A user can:

- create a new client certificate
- download the generated credential as **PKCS#12**
- enable or disable an existing certificate
- delete a certificate

The private key is generated in memory during certificate creation and is delivered to the user with the PKCS#12 file. Trustpoint stores the issued certificate and its association with the user.

Generated client certificates are intended for TLS client authentication and are linked to the corresponding Trustpoint user.

## Management CAs

Certificates used by Trustpoint itself (user authentication client certificates and
TLS server certificates) are issued by CAs with the **Management CA** role. CAs with
the **Issuing CA** role remain reserved for endpoint certificates (domains, devices,
agents) and cannot be selected for user authentication.

Management CAs reuse all existing CA key-storage and enrollment options:

- create a self-signed management CA from a chosen key algorithm and unique name
- import a key and certificate, or generate the key in the configured crypto backend
- request the certificate through EST, CMP, or an external CSR
- configure an external CA in EST/CMP RA mode

Self-signed management CAs use the default `issuing_ca` certificate profile for
their extensions and validity, and their subject marks them as self-signed.

The CA role is selected when the CA is created and cannot be changed afterwards.
Start the add wizard under **PKI → Issuing CAs → Add** and choose either
**Issuing CA** or **Management CA** before selecting the creation method.

Under **Management → User Authentication → Certificate** an administrator selects
the management CA used for user authentication. The page shows the current CA and
its certificate status; only active management CAs with a certificate are available
for selection. Certificate authentication is enabled separately on the
**User Authentication** page.

External CAs used for user authentication must be able to sign locally through
Trustpoint (a credential and certificate are required); pure RA-mode configurations
can be stored as management CAs but are not used for local certificate signing.
