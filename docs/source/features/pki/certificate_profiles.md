# Certificate Profiles

Certificate profiles define what issued certificates should look like. They combine template defaults with validation rules for incoming certificate requests, for example via CMP or EST.

Use certificate profiles to control:

- Subject attributes, such as `CN`, `OU`, or other DN fields
- X.509 extensions, such as Key Usage, Extended Key Usage, SAN, Basic Constraints, or CRL Distribution Points
- Certificate validity
- Whether request values may override profile defaults
- Which fields are required, allowed, fixed, or rejected

## Access

Certificate profiles are managed under:

`PKI > Certificate Profiles`

The overview lists all available profiles with their unique name, display name, domain usage, timestamps, default status, and available actions.

## Profile List

Each row represents one certificate profile.

| Column | Description |
| --- | --- |
| Unique Name | Internal profile identifier used by Trustpoint and request endpoints. |
| Display Name | Human-readable profile name. |
| Active in Domains | Shows where the profile is enabled. |
| Created at | Creation timestamp. |
| Updated at | Last update timestamp. |
| Is default | Indicates whether the profile is part of the default Trustpoint profiles. |
| Config | Opens the profile configuration. |
| Issuance | Starts certificate issuance using this profile, if available. |

Default profiles are provided for common use cases such as TLS client, TLS server, OPC UA, BACnet/SC, MQTT, IPsec IKE, EAP-TLS, IDevID, domain credentials, and issuing CA certificates.

## Protocol Profiles

Trustpoint includes these application profiles for protocol-specific certificate usages:

| Profile | Intended use | EKU | Identity requirements | Default validity |
| --- | --- | --- | --- | --- |
| `bacnet_sc` | BACnet/SC mutual TLS node certificates | `server_auth`, `client_auth` | Required common name and URI SAN based on the device UUID | 365 days |
| `mqtt_server` | MQTT broker/server TLS certificate | `server_auth` | Required DNS SAN; add every broker hostname clients use | 365 days |
| `mqtt_client` | MQTT client certificate for broker mutual TLS | `client_auth` | Required URI SAN based on the device UUID | 365 days |
| `ipsec_ike` | IKE certificate authentication | `ipsec_ike` | Required DNS SAN matching the peer's IKE FQDN identity; IP and RFC822 SANs are also allowed | 365 days |
| `eap_tls` | EAP-TLS peer/client authentication | `client_auth` | Required RFC822 SAN for the EAP identity | 365 days |

All five profiles are loaded from the default profile directory and use the existing database-backed profile selection in domain configuration, issuance UI, and the certificate-profile API. They are marked as default profiles, so newly created domains enable them automatically. Administrators should adjust required SAN values to match their deployment's actual protocol identities.

Profiles currently do not select an end-entity key algorithm. For Trustpoint-generated credentials, the generated key uses the domain issuing CA certificate's public-key algorithm and parameters. When a requester supplies a CSR, the CSR supplies the public key. Consequently, these profiles do not override the key algorithm or key parameters.

SSH certificates are not X.509 certificates and cannot be represented by these profiles. Trustpoint currently has no OpenSSH CA or SSH certificate issuance model, so SSH certificate profiles are not available.

## Managing Profiles

Certificate profiles are JSON documents. A profile must be enabled in a domain before devices can request certificates with it.

A domain may define an alias for a profile. This allows different internal profiles to be requested through the same profile name in different domains.

When a device requests a certificate, it selects the certificate profile through the request URL path.

## Profile Structure

A certificate profile can define the following root fields:

| Field | Description |
| --- | --- |
| `type` | Must be `cert_profile`. |
| `ver` | Optional schema version. |
| `display_name` | Human-readable name shown in Trustpoint. |
| `subject` | Defaults and constraints for the certificate subject. |
| `ext` / `extensions` | Defaults and constraints for X.509 extensions. |
| `validity` | Certificate validity settings. |

## Example

```json
{
  "type": "cert_profile",
  "ver": "1.0",
  "display_name": "Example TLS Server Profile",
  "subject": {
    "allow": ["CN", "OU"],
    "CN": {
      "required": true,
      "default": "device.example.com"
    }
  },
  "ext": {
    "key_usage": {
      "digital_signature": true,
      "key_encipherment": true,
      "critical": true
    },
    "extended_key_usage": {
      "usages": ["server_auth"]
    },
    "san": {
      "dns": ["device.example.com"]
    },
    "basic_constraints": {
      "ca": false,
      "critical": true
    }
  },
  "validity": {
    "days": 90
  }
}
```

## Supported Rules

| Rule | Description |
| --- | --- |
| `allow` | Allows additional fields. Use `"*"` or a list of field names. |
| `value` | Sets a fixed value. |
| `default` | Sets a default value if the request does not provide one. |
| `required` | Requires the field in the issued certificate. |
| `mutable` | Allows the request to override the profile value. |
| `reject_mods` | Rejects the request if it tries to modify the field. |
| `critical` | Marks an extension as critical. |
| `null` | Prohibits the field. |

Field names may use RFC 5280 names, OIDs, snake case, camel case, or supported abbreviations.

## Validity

The `validity` field defines how long issued certificates are valid.

Examples:

```json
{
  "validity": {
    "days": 90
  }
}
```

```json
{
  "validity": {
    "notBefore": "2026-01-01T00:00:00Z",
    "notAfter": "2027-01-01T00:00:00Z"
  }
}
```

```json
{
  "validity": {
    "duration": "P365D"
  }
}
```

Relative values such as `days`, `hours`, `minutes`, and `seconds` are added together.

Validity values are fixed by default. For example, `"validity": {"days": 10}`
issues certificates valid for 10 days and disables the Days field during manual
issuance. To let the requester change the relative validity, set `mutable` on
the validity object:

```json
{
  "validity": {
    "days": 10,
    "mutable": true
  }
}
```

During manual issuance, Days initially shows 10 and can be changed for that
certificate. The requested validity remains subject to the active security
policy's maximum certificate validity. Changing the profile affects future
issuance; it does not change certificates that have already been issued.

## CRL Distribution Points

Configure this extension to control where clients retrieve the issuing CA's
certificate revocation list (CRL). The URLs are added to the issued certificate's
X.509 CRL Distribution Points extension. Trustpoint's default CRL URLs use
HTTP, and its bundled web server serves `/crl/` over HTTP without redirecting
to HTTPS. Use HTTP URLs for Trustpoint-hosted CRLs.

1. Open the profile under **PKI > Certificate Profiles**.
2. In the profile builder, select **CRL Dist Points → URIs**.
3. Enter one or more comma-separated URLs. Use a fixed host or a supported placeholder.
4. Enable **Mutable** if users should be able to change the URLs during manual issuance.
5. Save the profile and select it when issuing a certificate for a device.

All shipped profiles except **Issuing CA** include this extension with
`http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}` and `mutable` enabled.
The active TLS certificate must have an IP SAN for this default
template to resolve; you can enter a fixed URL during manual issuance instead.
If your CRL endpoint uses a nonstandard port, include it explicitly in the URL.

The same configuration can be entered as JSON:

```json
{
  "type": "cert_profile",
  "validity": {"days": 30},
  "ext": {
    "crl_distribution_points": {
      "critical": false,
      "uris": {
        "value": ["http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}"],
        "mutable": false
      }
    }
  }
}
```

URL examples:

| URL | Behavior |
| --- | --- |
| `http://2.2.2.2/crl/{issuing_ca.id}` | Uses a fixed IPv4 address and the issuing CA's CRL endpoint. |
| `http://{tls_certificate.ip_address.1}/crl/{issuing_ca.id}` | Uses the first IP SAN of the active Trustpoint TLS certificate. |
| `http://crl.example.com/crl/4` | Uses a fully fixed URL for CA ID 4. |

Use `http://`, including both slashes; `http:2.2.2.2/...` is invalid.

`{tls_certificate.ip_address.1}` selects the first IP address in the active
Trustpoint TLS certificate's Subject Alternative Name extension; indices start
at 1. IPv6 addresses are enclosed in brackets automatically. `{issuing_ca.id}` is
the issuing CA's database ID used by Trustpoint's `/crl/<id>` endpoint, **not**
the CRL's changing sequence number. Double braces, such as `{{ issuing_ca.id }}`,
are accepted as well. Unavailable IP addresses and unsupported placeholders
cause validation to fail rather than being included in an issued certificate.

For example, if the first TLS IP SAN is `192.0.2.10` and the issuing CA's ID is
`4`, the template in the JSON example produces `http://192.0.2.10/crl/4`.

The manual issuance form displays **CRL Distribution Point URLs** with the
placeholders already resolved to the active TLS certificate's IP address and
the issuing CA's ID. The profile retains its template for future issuance.
If an IP SAN is unavailable, the form shows an explanation; an editable field
can be replaced with a fixed URL.

With
`"mutable": false`, the field is disabled and submitted changes cannot override
the profile value. With `"mutable": true`, users can edit the comma-separated
URLs for that issuance. Use `default` instead of `value` for an initial suggestion.
Changing a profile affects future issuance; existing certificates retain their
original distribution points.

URLs must be
absolute ASCII URLs with a scheme and host. Profiles without configured CRL
URLs retain Trustpoint's automatic distribution point based on TLS settings
and the configured HTTP port.

## Template Variables

String values in a profile may contain `{{ namespace.field }}` placeholders. They are resolved after the profile has been applied to the request, using the device and domain the certificate is issued for.

| Variable | Value |
| --- | --- |
| `{{ device.id }}` | Internal Trustpoint ID of the device. |
| `{{ device.rfc_4122_uuid }}` | UUID of the device. |
| `{{ device.common_name }}` | Common name of the device. |
| `{{ device.serial_number }}` | Serial number of the device. |
| `{{ device.device_type }}` | Device type, e.g. `Generic Device` or `OPC UA GDS Push`. |
| `{{ device.ip_address }}` | IP address of the device. Only available if set. |
| `{{ device.opc_server_port }}` | OPC UA server port of the device. Only available if set. |
| `{{ domain.unique_name }}` | Unique name of the device's domain. |
| `{{ domain.issuing_ca }}` | Unique name of the domain's issuing CA. Only available if set. |
| `{{ domain.organization }}` | Organization Name (O) of the domain's assigned organization. |
| `{{ domain.organization_unit }}` | Organizational Unit (OU) of the domain's assigned organization. |
| `{{ domain.country }}` | Country (C) of the domain's assigned organization. |
| `{{ domain.state }}` | State or Province (ST) of the domain's assigned organization. |
| `{{ domain.locality }}` | Locality (L) of the domain's assigned organization. |
| `{{ time.now }}` | Current UTC time in ISO 8601 format. |
| `{{ time.date }}` | Current UTC date (`YYYY-MM-DD`). |
| `{{ time.timestamp }}` | Current Unix timestamp in seconds. |

Organization variables are available only when an organization is assigned to the domain. Values come directly from that organization; unset fields resolve to empty strings.

Unknown general template variables are left unchanged and logged as a warning. General template variables are also resolved in the initial values of the manual issuance form. CRL URL placeholders follow the stricter validation rules described in [CRL Distribution Points](#crl-distribution-points) and are resolved in the manual form's initial values and again during issuance.

Example: bind a certificate to a device through SAN URI entries:

```json
"subject_alternative_name": {
  "uris": {
    "value": [
      "urn:device:common-name:{{ device.common_name }}",
      "urn:device:serial-number:{{ device.serial_number }}",
      "urn:device:domain:{{ domain.unique_name }}",
      "urn:device:uuid:{{ device.rfc_4122_uuid }}"
    ]
  }
}
```

## Validation Flow

For each certificate request, Trustpoint:

1. Parses the incoming request.
2. Converts it into an internal certificate request structure.
3. Validates and normalizes the selected certificate profile.
4. Validates and normalizes the request.
5. Applies the profile rules to the request.
6. Resolves template variables.
7. Builds the certificate from the validated result.

Invalid requests are rejected or normalized according to the selected profile rules.
