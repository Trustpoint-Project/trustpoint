(trustpoint-agents)=
# Trustpoint Agents

Trustpoint Agents enable automated certificate lifecycle management for devices in industrial environments. Agents can manage certificates for standalone devices (1-to-1) or handle multiple devices within a production cell (1-to-n).

## Overview

Agents are lightweight Python (as of now) applications that run within production environments and communicate with Trustpoint via secure mTLS connections. They automate certificate enrollment, renewal, and deployment workflows, reducing manual intervention and ensuring devices always have valid credentials.

### Key Features

- **Automated Certificate Renewal**: Agents poll Trustpoint for due certificate renewals and automatically execute the renewal workflow
- **Flexible Deployment**: Support for both 1-to-1 (single device) and 1-to-n (multiple managed devices) architectures
- **Secure Communication**: All API communication uses mutual TLS (mTLS) with domain credentials
- **Workflow Automation**: Execute custom workflows for certificate deployment, including web-based management (WBM) interactions
- **Resilient Operation**: Built-in retry logic and error handling for transient failures
- **Structured Logging**: JSON or text logging for integration with monitoring systems

## Agent Types

### 1-to-1 Agents

A 1-to-1 agent runs directly on the target device. The agent process and the device are one and the same, using the device's domain credential for authentication.

**Use Cases:**
- Linux servers or embedded devices with sufficient resources
- Devices that need to manage their own certificates
- Standalone industrial controllers with network connectivity

**Example:**
```bash
python agent.py --profile agent_setup.json
```

## Workflow Definitions

Workflow definitions (also called "profiles") describe the automation steps an agent should execute to deploy a certificate to a device. These are reusable templates that can be assigned to multiple agents or devices.

### Profile Structure

A workflow profile contains:

- **Metadata**: Agent type, version, description
- **Device Information**: Vendor, device family, firmware version
- **Local storage**: Onformation on where files are located and stored
- **Certificate Request**: Profile name, enrollment URL, subject/SAN parameters


### Example Workflow

```json
{
  "type": "agent_profile",
  "name": "TLS Webserver Certificate",
  "profile": {
    "metadata": {
      "agent_type": "1-to-1",
      "version": "1.0",
      "description": "Request policy for a 1-to-1 agent TLS webserver certificate. Used for HTTPS servers, web interfaces, and other TLS-enabled services."
    },
    "device": {
      "vendor": "Generic",
      "device_family": "Webserver",
      "firmware_hint": "1.0"
    },
    "local_storage": {
      "os_path": "/etc/trustpoint/certs",
      "certificate_path": "{{ os_path }}/{{ common_name }}-certificate.pem",
      "certificate_chain_path": "{{ os_path }}/{{ common_name }}-full-chain.pem",
      "csr_path": "{{ os_path }}/{{ common_name }}-csr.pem",
      "private_key_path": "{{ os_path }}/{{ common_name }}-key.pem",
      "crl_path": "{{ os_path }}/{{ common_name }}-crl.pem"
    },
    "certificate_request": {
      "certificate_profile": "tls_server",
      "url": "{{ endpoint }}",
      "path": "{{ path }}",
      "subject": "{{ subject }}",
      "subject_alt_name": "{{ subject_alt_name }}",
      "public_key_algorithm_oid": "{{ public_key_algorithm_oid }}",
      "key_parameter": "{{ key_parameter }}"
    }
  }

```

**Template Variables:**

The profile can use these template variables that are resolved when sent to the agent:

- `{{ os_path }}` - Base directory path from the agent's configuration (e.g., "/Users/user/certs", "/etc/trustpoint")
- `{{ common_name }}` - The Common Name (CN) for this certificate assignment (e.g., "webserver.example.com", "api-server.local")
- `{{ endpoint }}` - Trustpoint enrollment endpoint URL
- `{{ path }}` - Certificate enrollment path based on certificate_profile
- `{{ subject }}` - Subject DN configured for this profile assignment (with CN automatically added)
- `{{ subject_alt_name }}` - SAN extension configured for this profile assignment
- `{{ public_key_algorithm_oid }}` - Public key algorithm OID from domain
- `{{ key_parameter }}` - Key size (RSA) or curve name (ECC) from domain
- `{{ certificate_profile }}` - The certificate profile name from certificate_request

**Note:** The `{{ common_name }}` is mandatory for each profile assignment and must be unique per agent. It serves two purposes:
1. **Certificate Identity**: Used as the Common Name (CN) in the certificate subject
2. **File Management**: Used in file paths to ensure different certificates don't overwrite each other

The `{{ os_path }}` variable uses the agent's configured base directory, ensuring all certificates are stored in the same location as the agent's domain credential.

## Agent API

Agents communicate with Trustpoint through REST API endpoints using mTLS authentication.


## Agent Onboarding

Before an agent can start managing certificates, it must be onboarded to Trustpoint:

1. **Create Agent Record**: Register the agent in Trustpoint (Devices → Agents)
2. **Generate Agent Profile**: Trustpoint generates an `agent_setup.json` file with:
   - Onboarding credentials (device name and shared secret)
   - Trustpoint TLS certificate
   - Enrollment endpoint URL
   - Certificate request parameters
   - Local file paths for key/certificate storage

3. **Initial Enrollment**: The agent uses the profile to:
   - Generate a private key
   - Create a certificate signing request (CSR)
   - Authenticate with HTTP Basic Auth (device name + secret)
   - Receive domain credential from Trustpoint

4. **Start Polling**: With the domain credential, the agent enters its polling loop

## Assigned Profiles

For each agent (or managed device for 1-to-n agents), you can assign one or more workflow profiles that define which certificates should be managed and when they should be renewed.

### Profile Assignment

- **Renewal Threshold**: Days before expiry to trigger renewal
- **Subject/SAN**: Certificate subject and subject alternative names
- **Scheduling**: Next scheduled renewal time
- **Enable/Disable**: Toggle profile execution without deletion

### Renewal Logic

Trustpoint automatically schedules renewals based on:
- Certificate expiration date
- Configured renewal threshold
- Last successful update timestamp
- Manual override schedules
