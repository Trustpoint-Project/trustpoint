(devices)=
# Devices

Trustpoint manages device identities and certificates throughout their lifecycle.
Use the **Devices** section to register devices, configure enrollment, and manage
their credentials.

## Device Management

A device record contains identifying information, such as its name and serial
number, and its enrollment configuration. Assign a device to a domain to use
that domain's certificate issuance settings and profiles.

Trustpoint distinguishes between domain credentials and application certificates:

- **Domain credentials** identify a device when it authenticates with Trustpoint
  after onboarding.
- **Application certificates** secure the services and applications running on
  the device, such as TLS servers and clients.

Devices can also be configured without onboarding when a domain credential is
not required. Available enrollment and management operations depend on the
device's configuration.

## Management Options

| Option | Purpose |
|---|---|
| [Onboarding](onboarding.md) | Establish a device identity using the supported onboarding mechanisms. |
| [Trustpoint Agents](agents.md) | Automate certificate enrollment, renewal, and deployment with an agent running on the device. |
| [OPC UA GDS](opc_ua_gds.md) | Manage OPC UA server certificates and trustlists through GDS Push. |

## Getting Started

1. Configure a [domain](../pki/domains.md) and its certificate profiles.
2. Register the device and select the appropriate device type and onboarding method.
3. Complete onboarding if the device uses a domain credential.
4. Issue application certificates and configure the available renewal options.

```{toctree}
:maxdepth: 2

onboarding
agents
opc_ua_gds
```
