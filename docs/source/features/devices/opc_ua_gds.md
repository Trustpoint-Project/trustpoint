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
actually produced a new key. A server that changes these values or ignores the
rollover is rejected with an explanatory error. After `ApplyChanges`, Trustpoint
reconnects and reports whether the new certificate/trustlist is usable; a
reconnect failure does not mark an already-applied update as failed.

For devices with fixed trustlist capacity, configure **Maximum entries** and
**Maximum element size** in the renewal settings. Limits count unique
certificates and CRLs; `0` disables a limit. The server's advertised
`MaxTrustListSize` is also enforced. For example, some S7-1500 firmware documents
a limit of 62 entries and 4,096 bytes per element; verify the values for your
device.

**Require CRLs in pushed trustlists** is enabled by default. Disable it only for
devices whose CA chain legitimately has no CRL; otherwise strict revocation
checks can reject later certificate updates.

Generate CRLs for the CAs included in the trustlist before performing a trustlist
update. Trustpoint requires CRLs for GDS Push trustlist operations.

## Periodic Renewal

Periodic server certificate and trustlist renewal can be enabled for a device.
Configure the renewal interval in hours; the minimum interval is one hour.
Scheduled operations require a running Trustpoint task worker. The trust list is
refreshed each cycle; the server certificate is only replaced when it expires
within the configured **Certificate renewal threshold (days)** (default 30).

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
