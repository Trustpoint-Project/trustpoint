Issued Certificate Defaults
===========================

This section gives details about the contents of specific issued certificates and credentials.

Domain Credentials
------------------
Domain Credential Certificates will always contain the following subject.

All Domain Credentials are valid for 47 days by default.
This value follows from WebPKI rules as sensible default, however this can be adjusted for the actual environment.
If no automation of the renewal process is possible, this default may be set higher.
For more critical environments, a shorter duration may be set.

.. list-table:: Domain Credential Certificate Subject
   :widths: 50 50 50
   :header-rows: 1

   * - DN Attribute Type (Name)
     - DN Attribute Type (OID)
     - DN Attribute Value
   * - Common Name (CN)
     - 2.5.4.3
     - Trustpoint Domain Credential
   * - Domain Component (DC)
     - 0.9.2342.19200300.100.1.25
     - <unique name of the corresponding domain>
   * - Serial Number
     - 2.5.4.5
     - <serial number of the corresponding device>


Application Credentials
-----------------------

All Application Credentials are valid for 47 days by default.
This value follows from WebPKI rules as sensible default, however this can be adjusted for the actual environment.
If no automation of the renewal process is possible, this default may be set higher.
For more critical environments, a shorter duration may be set.

TLS Client Credentials
......................

.. list-table:: TLS Client Credential Certificate Subject
   :widths: 50 50 50
   :header-rows: 1

   * - DN Attribute Type (Name)
     - DN Attribute Type (OID)
     - DN Attribute Value
   * - Common Name (CN)
     - 2.5.4.3
     - <required: can be chosen arbitrarily, but will be unique within the domain>
   * - Pseudonym
     - 2.5.4.65
     - Trustpoint Application Credential - TLS Client
   * - Domain Component (DC)
     - 0.9.2342.19200300.100.1.25
     - <unique name of the corresponding domain>
   * - Serial Number
     - 2.5.4.5
     - <serial number of the corresponding device>

.. note::

    The Common Name (CN) chosen will be unique within the domain. There can only be one valid certificate / credential
    at one time, however, there can be other certificates with the same domain and common name if these are expired or
    have been revoked.

    This unique constraint is also enforced for different kinds of application certificates.
    E.g., It is not possible to use the same common name for both a TLS client and TLS server certificate.

    The common name: Trustpoint Domain Credential is forbidden.


TLS Server Credentials
......................

.. list-table:: TLS Server Credential Certificate Subject
   :widths: 50 50 50
   :header-rows: 1

   * - DN Attribute Type (Name)
     - DN Attribute Type (OID)
     - DN Attribute Value
   * - Common Name (CN)
     - 2.5.4.3
     - <required: can be chosen arbitrarily, but will be unique within the domain>
   * - Pseudonym
     - 2.5.4.65
     - Trustpoint Application Credential - TLS Server
   * - Domain Component (DC)
     - 0.9.2342.19200300.100.1.25
     - <unique name of the corresponding domain>
   * - Serial Number
     - 2.5.4.5
     - <serial number of the corresponding device>

.. note::

    The Common Name (CN) chosen will be unique within the domain. There can only be one valid certificate / credential
    at one time, however, there can be other certificates with the same domain and common name if these are expired or
    have been revoked.

    This unique constraint is also enforced for different kinds of application certificates.
    E.g., It is not possible to use the same common name for both a TLS client and TLS server certificate.

    The common name: Trustpoint Domain Credential is forbidden.

The TLS Server Credential Subject Alternative Name (SAN) Extension does not have a default set. It must be
provided by the request. At least one of the following has to be provided by the request:

- IPv4 Address
- IPv6 Address
- Domain Name

