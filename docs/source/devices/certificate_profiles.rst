.. _certificate-profiles:

====================
Certificate Profiles
====================

A Certificate profile combines template defaults and a constraint policy for certificate requests to Trustpoint (e.g. via CMP or EST).
They are used to validate the content of certificate requests and to ensure that the issued certificates meet specific, customizable requirements.

The following diagram illustrates the process of certificate profile validation:

.. plantuml:: ../diagrams/cert_profile_overview.puml
    :caption: Certificate Profile validation process

Managing Certificate Profiles
-----------------------------

Certificate profiles are specified as JSON documents and can be managed in the PKI section of the Trustpoint web interface.
After creating a new certificate profile, it must be explicitly enabled in the domain to allow devices to request certificates using that profile.
It is possible to set an optional alias within the domain. That way, you can e.g. have two different domain credential profiles ``domain_credential_a`` and ``domain_credential_b``,
but both can be requested using the same certificate profile alias ``domain_credential`` in their domains ``A`` and ``B``, respectively.
When a device requests a certificate, it must specify the desired certificate profile in the URL path segment.

Certificate Profile Structure
-----------------------------

A certificate profile JSON document has up to six root-level fields:
- ``type``: Must be set to ``cert_profile``. Used to distinguish certificate profiles from other JSON documents.
- ``ver``: Optional version string of the certificate profile schema. This document describes version ``"0.1"``.
- ``subject``: Defines defaults and constraints for the Subject DN of the issued certificate.
- ``extensions``: Defines defaults and constraints for X.509 extensions in the issued certificate.
- ``validity``: Defines defaults and constraints for the validity period of the issued certificate.
- ``display_name``: Optional human-readable name for the certificate profile used throughout Trustpoint.

Here is an example of a short certificate profile JSON document:

.. code-block:: json

  {
    "type": "cert_profile",
    "ver": "1.0",
    "subject": {
      "allow": "*",
      "CN": {
        "required": true,
        "default": "device.example.com"
      }
      "OU": null
    },
    "ext": {
        "allow":
        "key_usage": {
            "digital_signature": true,
            "key_encipherment": true,
            "critical": true
        },
        "extended_key_usage": {
            "usages": ["server_auth", "client_auth"]
        },
        "san": {
            "dns": ["device.example.com"],
            "ip": ["192.0.2.1"]
        },
        "basic_constraints": {
            "ca": false,
            "critical": true
        }
    },
    "validity": {
      "days": 42
    },
    "display_name": "Example Certificate Profile"
  }

Valid field name identifiers include the names defined in RFC 5280 for Subject DN attributes and X.509 extensions in snake and camel case (e.g., ``key_usage`` or ``keyUsage``), the correspondending OID (``2.5.29.15``) as well as select abbreviations (e.g. ``ku``).

Additionally, the following special fields are supported for setting defaults and constraints:

- ``allow``: A wildcard string (``"*"``) or a list of allowed field names (``["CN", "OU"]``). Specifies which fields are allowed in addition to the explicitly defined fields. If omitted, no additional fields are allowed.
- ``value``: Explicitly sets a default value for a field (``{"CN": {"value": "example.com"}}``). If no other field constraints are defined, the value can be set directly (``"CN": "example.com"``). Setting a value of ``null`` (``"OU": null``) prohibits the field entirely.
- ``mutable``: Boolean flag (``true`` or ``false``). Specifies whether a field's value in the profile can be overridden by the certificate request. Inherited from parent fields. Defaults to ``false``.
- ``required``: Boolean flag (``true`` or ``false``). Specifies whether a field must be present in the issued certificate.
- ``default``: Sets a default value for a field if it is not provided in the certificate request. Always mutable.
- ``reject_mods``: Boolean flag (``true`` or ``false``). If set to ``true``, any modifications to this field in the certificate request will cause the request to be rejected. If false, the request is modified to match the profile constraints. Inherited from parent fields. Defaults to ``false``.
- ``critical``: Extensions only. Boolean flag (``true`` or ``false``). Specifies whether an X.509 extension should be marked as critical in the issued certificate.

Validity
^^^^^^^^

The ``validity`` field defines the validity period of the issued certificate. It supports the following sub-fields:

.. code-block:: json
  {
    "validity": {
      // Method 1: Explit ISO 8601 timestamps
      "notBefore": "2023-10-01T00:00:00Z",
      "notAfter": "99991231T235959Z", // example - IDevID
      // Method 2: Relative validity period (from notBefore, defaults to now)
      "days": 90,
      "hours": 6,
      "minutes": 30,
      "seconds": 0, // these are added up, so {"days":2,"hours":48} would be 4 days actually
      // Method 3: Validity as ISO 8601 duration
      "duration": "P365D",
    }
  }

Pydantic V2 is used for profile schema validation and alias handling.
