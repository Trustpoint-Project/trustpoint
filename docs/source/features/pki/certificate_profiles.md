# Certificate Profiles

Certificate profiles define what issued certificates should look like. They combine template defaults with validation rules for incoming certificate requests, for example via CMP or EST.

Use certificate profiles to control:

- Subject attributes, such as `CN`, `OU`, or other DN fields
- X.509 extensions, such as Key Usage, Extended Key Usage, SAN, or Basic Constraints
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

Default profiles may be provided for common use cases such as TLS client, TLS server, OPC UA, IDevID, domain credentials, and issuing CA certificates.

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

## Validation Flow

For each certificate request, Trustpoint:

1. Parses the incoming request.
2. Converts it into an internal certificate request structure.
3. Validates and normalizes the selected certificate profile.
4. Validates and normalizes the request.
5. Applies the profile rules to the request.
6. Builds the certificate from the validated result.

Invalid requests are rejected or normalized according to the selected profile rules.