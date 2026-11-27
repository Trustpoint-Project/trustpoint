(opc-ua-gds)=
# OPC UA GDS

Trustpoint supports OPC UA Global Discovery Server (GDS) Push for managing
certificates and trustlists on OPC UA servers. Trustpoint connects to the server
and performs certificate management operations through its OPC UA interface.

Register these servers as **OPC UA GDS Push** devices in the **Devices** section.

## Requirements

Before configuring a device, prepare:

- An OPC UA server that supports GDS Push certificate and trustlist management.
- A network connection from Trustpoint to the server's IP address and OPC UA port.
- A Trustpoint domain with an issuing CA and suitable certificate profiles.
- A truststore for verifying the OPC UA server.
- The server's security administration credentials, if username and password
  authentication is used.

For certificate-based authentication, the server must trust Trustpoint's client
certificate and grant it the permissions required for certificate management.
Trustpoint negotiates the strongest `SignAndEncrypt` security policy the server
advertises (AES policies first, then `Basic256Sha256`).

## Register and Configure a Server

1. Create an **OPC UA GDS Push** device.
2. Enter its name, IP address, and OPC UA server port. The standard port is `4840`.
   Alternatively, enter a full **OPC Server URL** such as
   `opc.tcp://public.example:4840/plant/edge`; it overrides the IP and port and
   preserves the resource path for NAT, Docker or reverse-proxy setups.
3. Assign the device to the domain used for certificate issuance.
4. If required by the server, enter an OPC UA username and password with the
   **SecurityAdmin** role. Leave both fields blank to use certificate-based
   authentication.
5. Configure the domain to use the **OPC UA Domain Credential** profile and issue
   the device's domain credential.
6. Associate a truststore with the device to verify the OPC UA server. If the
   server certificate is not trusted yet, run **Discover Server** and download
   the discovered certificate, then import it as an OPC UA GDS Push truststore.

Use the device's certificate lifecycle management and help pages to access the
available GDS Push operations.

## Certificate and Trustlist Management

Trustpoint provides operations to:

- Discover the server's endpoints and certificate management capabilities.
- Update the server's trustlist with certificates and certificate revocation
  lists (CRLs).
- Request a certificate signing request from the server, issue a replacement
  server certificate, and push it to the server.

Trustpoint reads the server's current trustlist and merges its CA chain and CRLs
into it, so existing trust entries are preserved. The root CA is installed as
the trust anchor; issuing and intermediate CAs are installed as issuers. The
server's rejected certificates are read and logged; they are not trusted
automatically. A certificate renewal applies the trustlist first.

Before signing the server's CSR, Trustpoint verifies that it keeps the current
Common Name, ApplicationUri and DNS/IP SANs, and that a requested key rollover
actually produced a new key. A server that changes these values is rejected with
an explanatory error. If the server cannot generate a key, or ignores a requested
rollover, Trustpoint generates one and uploads it in a format the server
advertises (PFX, PEM or PKCS#8). After `ApplyChanges`, Trustpoint reconnects and
reports whether the new certificate/trustlist is usable; a reconnect failure does
not mark an already-applied update as failed.

For devices with fixed trustlist capacity, configure **Maximum entries** and
**Maximum element size** in the renewal settings. Limits count unique
certificates and CRLs; `0` disables a limit. The server's advertised
`MaxTrustListSize` is also enforced. For example, some S7-1500 firmware documents
a limit of 62 entries and 4,096 bytes per element; verify the values for your
device.

**Require CRLs in pushed trustlists** is enabled by default. Disable it only for
devices whose CA chain legitimately has no CRL; otherwise strict revocation
checks can reject later certificate updates.

Issued certificate key sizes, RSA minima, permitted ECC curves and blocked
signature hashes come from the central **Security Configuration**
(`SecurityConfig`). Trustpoint validates the server CSR and the issued
certificate against that policy before deployment. Do not duplicate those
settings per device; a stricter device validation policy must be aligned out of
band because it is not readable over OPC UA.

**OPC UA security policies** are selected from the
`SecurityConfig.permitted_opc_ua_security_policies` allow-list. Trustpoint reads
the server's SignAndEncrypt endpoints and picks the strongest permitted policy.
It never falls back to a disabled or legacy policy. `Basic256` and
`Basic128Rsa15` must be enabled explicitly and are marked as legacy. If no
permitted policy is compatible with the server's endpoints and the configured
RSA/ECC rules, the operation fails with the advertised and permitted lists.
The Python OPC UA client library does not implement the ECC SecurityPolicies, so
ECC-only endpoints are reported as incompatible rather than selected.

**Server certificate validation** defaults to pinning the certificate at
truststore order 0. Select **CA chain validation** when the server certificate
rotates: Trustpoint then reads the current certificate from the server's
discovery endpoint and accepts it only when it chains to a CA in the associated
truststore. Pinning fails closed on any change; CA validation still rejects
certificates that are expired, untrusted or not issued by the configured CAs.

Generate CRLs for the CAs included in the trustlist before performing a trustlist
update. Trustpoint requires CRLs for GDS Push trustlist operations.

## Certificate Inventory

**Refresh Certificate Inventory** reads the current certificate groups,
certificate type slots, subjects, expiry dates and SHA-256 fingerprints from the
device, together with trust-list entry counts and the server's rejected-
certificate list. The snapshot is stored on the device and shown on the help
page. Use it to confirm what the device actually holds rather than relying on the
last successful deployment.

## Permissions

Every push, inventory refresh and renewal-settings action requires the
`users.manage_gds_push` permission in addition to the action's own permission
(`manage_devices` for trust lists and settings, `issue_certificates` for server
certificates). Grant it only to roles that should be able to change the device's
certificates. The built-in Device Operator and PKI Admin roles include it.

## Periodic Reconciliation

Periodic reconciliation can be enabled for a device. Configure the interval in
hours; the minimum interval is one hour. Scheduled operations require a running
Trustpoint task worker. The interval controls how often the task reconciles
state; it does not force a certificate renewal.

Each cycle evaluates the two sides independently:

- **Certificate groups** are checked against the device's actual inventory.
  A group is renewed only when its current certificate expires within the
  configured **Certificate renewal threshold (days)** (default 30).
- **Trust lists** are compared with the desired contents. Unchanged lists are
  skipped and no `ApplyChanges` is sent. Changes to CA certificates, CRLs or
  managed trust relationships trigger a synchronisation.

Trustpoint-managed CA certificates and CRLs that are no longer in the desired
list are pruned; entries not managed by Trustpoint are preserved. If a
certificate must be renewed, the trust list is brought up to date first so the
issuer certificates and CRLs are present before activation.

The periodic run is also the fallback for missed events, offline devices and
configuration drift. To renew a certificate immediately, use **Update Server
Certificate**; that action remains an explicit forced renewal independent of the
expiry threshold. Device operations are serialised by a database-backed
per-device lock, so multiple task workers do not push to the same device
concurrently.

By default the server's existing private key is reused for each renewal. Enable
**Generate a new server private key on renewal** to roll the key; this is
required only when the old key must be replaced, and may not be possible on
servers with secure elements or non-exportable keys.

Domain credential renewal is configured separately. When enabled, Trustpoint
replaces the domain credential and revokes its predecessor at the configured
interval.

## Troubleshooting

If an operation fails, check that the server is reachable at the configured IP
address and port, supports the requested GDS Push operation, and grants the
configured identity the required permissions. Verify the associated truststore
and the availability of CRLs for trustlist updates.

See [Onboarding Mechanisms](onboarding.md) for other device enrollment options
and [Domains](../pki/domains.md) for domain configuration.
