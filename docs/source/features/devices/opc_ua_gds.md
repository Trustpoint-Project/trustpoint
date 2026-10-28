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

## Register and Configure a Server

1. Create an **OPC UA GDS Push** device.
2. Enter its name, IP address, and OPC UA server port. The standard port is `4840`.
3. Assign the device to the domain used for certificate issuance.
4. If required by the server, enter an OPC UA username and password with the
   **SecurityAdmin** role. Leave both fields blank to use certificate-based
   authentication.
5. Configure the domain to use the **OPC UA Domain Credential** profile and issue
   the device's domain credential.
6. Associate a truststore with the device to verify the OPC UA server.

Use the device's certificate lifecycle management and help pages to access the
available GDS Push operations.

## Certificate and Trustlist Management

Trustpoint provides operations to:

- Discover the server's endpoints and certificate management capabilities.
- Update the server's trustlist with certificates and certificate revocation
  lists (CRLs).
- Request a certificate signing request from the server, issue a replacement
  server certificate, and push it to the server.

Generate CRLs for the CAs included in the trustlist before performing a trustlist
update. Trustpoint requires CRLs for GDS Push trustlist operations.

## Periodic Renewal

Periodic server certificate and trustlist renewal can be enabled for a device.
Configure the renewal interval in hours; the minimum interval is one hour.
Scheduled operations require a running Trustpoint task worker.

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
