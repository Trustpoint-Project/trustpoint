.. _aoki:

==============================================
Automated Onboarding Key Infrastructure (AOKI)
==============================================

*Revision v0.2*

This document describes the **Automated Onboarding Key Infrastructure**
(AOKI) and the protocols it defines. Fig. 1 gives a high level overview
of the three stages the infrastructure is composed of - Device
Initialization, Device Ownership Transfer Authorization, and the actual
Zero-Touch Device Onboarding.

.. figure:: /_static/aoki.png
   :alt: Fig. 1

   AOKI overview

Overview
--------

Automated Onboarding Key Infrastructure (AOKI) is a protocol that
simplifies zero-touch onboarding and is currently in a Proof-of-concept
phase in the Trustpoint project. It is inspired by concepts from
standardized Zero-Touch protocols BRSKI (RFC 8995) and FIDO FDO, but
differs in key aspects. At the time of device onboarding, AOKI works
fully offline, without the need for a connection to an external service
like a MASA or a Rendezvous Server. The only requirement for onboarding
to be possible is the Device having a connection to the AOKI Owner
Service, which is usually present on the same host as the networks RA
functionality for certificate enrollment (e.g. Trustpoint/other EST
server) The initial method by which the device discovers the AOKI Owner
Service is flexible - for local environments, mDNS (Zeroconf) appears
like a suitable solution. AOKI offers mutual trust verification -
therefore there are no security implications due to *Trust on First
Use*. The Owner Service verifies the device via a standard IEEE 802.1AR
IDevID certificate. The device verifies the owner by a certificate we
call a DevOwnerID, the device trusts the issuer of this certificate
(usually the manufacturer). A DevOwnerID certificate is a standard X.509
certificate with a Subject Alternative Name extension that contains
identifiers for all IDevID(s) the DevOwnerID is valid for. The trust
establishment is currently based on mutual TLS with a custom HTTP GET
init request, though the team is also drafting an alternative approach
working exclusively over CMP. After trust establishment, actual
enrollment is handled by standard PKI protocols like EST and CMP.

Goals
-----

- The implemented solution shall use secure device identities (DevIDs),
  according to IEEE 802.1AR
- The solution offers automatic mutual authentication (no trust on first
  use)

  - The network runs an Owner Service that verifies identity using the
    manufacturer IDevID PKI
  - Device verifies Owner identity using an X.509 certificate called the
    DevOwnerID (issued by a (manufacturer) CA the device trusts)

- The solution offers link-local owner service discovery

  - e. g. multicastDNS

- The solution should not depend on third parties
- No dependency on the manufacturer or previous owner at the time of
  onboarding

Definitions
-----------

The *Device* represents a new entity to be added to a network.

The *Owner Service* is the entity within the network responsible for
initial onboarding of new Devices via AOKI. It typically performs the
services of a Registration Authority (RA) and it would be a common
scenario to host the Owner Service on the same hostname/server as the RA
offering PKI services such as an EST server.

The DevOwnerID
^^^^^^^^^^^^^^

The DevOwnerID is a standard X.509 certificate.

Attributes
~~~~~~~~~~

There are no required fields in the certificate subject Distinguished
Name (DN). It is RECOMMENDED that a the ``pseudonym`` name attribute
with value ``DevOwnerID``\ is added, this is only intended to simplify
distinguishing DevOwnerIDs from other types of certificates.

   Note: The Serial Number attribute is of type PrintableString, so the
   character ``_`` MUST NOT be used. It is RECOMMENDED to replace any
   spaces or underscores in the manufacturer-defined serial number with
   a hyphen (``-``).
   
Extensions
~~~~~~~~~~

The certificate MUST have a ``BasicConstraints`` extension marked as critical.
Conforming DevOwnerIDs SHOULD be CA certificates to facilitate transfer of
device ownership. The ``pathLenConstraint`` MUST be absent to
facilitate an arbitrary amount of device ownership transfers.

The DevOwnerID MUST have a ``SubjectAltName`` extension that lists the
IDevID certificate(s) the DevOwnerID is valid for. Each IDevID is listed
as a ``UniformResourceIdentifier`` (URI) with the fixed format:
``dev-owner:<IDevID_Subj_SN>.<IDevID_x509_SN>.<IDevID_SHA256_Fingerpr>``,
where: - ``IDevID_Subj_SN`` is the ``SerialNumber`` name attribute in
the IDevID subject DN; or the character ``_`` (underscore) if this
attribute is not present in the IDevID certificate - ``IDevID_x509_SN``
is the X.509 Serial Number in lower case hexadecimal notation. -
``IDevID_SHA256_Fingerpr`` is the SHA256 fingerprint of the IDevID
certificate in lower case hexadecimal notation.

Issuer
~~~~~~

The DevOwnerID is issued by a CA that is trusted by the device. A
reasonable choice is an DevOwnerID Root CA generated exclusively for the
DevOwnerID chain corresponding to each given IDevID or set of IDevIDs
belonging together. While it appears a straightforward choice, the same
CA as for issuing IDevIDs SHOULD NOT be used to issue DevOwnerID
certificates, as standard PKI verification tools may verify unauthorized
IDevIDs issued by DevOwnerIDs. The only type of certificate a DevOwnerID
is allowed to issue is another DevOwnerID with identical or a subset of
the IDevID identifiers in its SAN, though it is not yet specified how to
best enforce this constraint on the PKI level.

Validity
~~~~~~~~

The DevOwnerID SHOULD have a ``notValidAfter``\ equal to the
``notValidAfter`` of the IDevID that expires last among the ones
referenced in the certificate. It is recommended to use a
``notValidAfter`` of ``99991231235959Z``. ``notValidBefore``\ MAY be set
to the earliest ``notValidBefore`` among the referenced IDevID
certificates.

Device Initialization
---------------------

This stage involves initial provisioning of the Device with an IDevID
and associated Owner Truststore. It is not yet specified in detail in
this document.

Device Ownership Transfer Authorization
---------------------------------------

This stage involves using the initial DevOwnerID (or Root CA) to issue a
new DevOwnerID to the new Owner of the Device - for example, if the
Device is sold by its manufacturer to a supplier or an operator. It is
not yet specified in detail in this document.

AOKI Zero-Touch Device Onboarding
---------------------------------

This stage entails the actual automatic onboarding of the device to the
network of the new Owner.

For Zero-Touch Device Onboarding to succeed, the following prerequisites
must be met:

+-----------------------+-----------------------+-----------------------+
|                       | AOKI - flexible       | AOKI via CMP          |
|                       | enrollment protocol   |                       |
+=======================+=======================+=======================+
| Device Requirements   | IDevID, Owner         | IDevID, Owner         |
|                       | Truststore, TLS       | Truststore            |
|                       | client authentication |                       |
+-----------------------+-----------------------+-----------------------+
| Owner Service         | DevOwnerID, IDevID    | DevOwnerID, IDevID    |
| Requirements          | Truststore, TLS       | Truststore, HTTP      |
|                       | server with client    | server                |
|                       | auth support          |                       |
+-----------------------+-----------------------+-----------------------+

AOKI Mutual TLS Device Onboarding with flexible enrollment protocol
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This AOKI Device Onboarding protocol variant is designed to be agnostic
both to the utilized Owner Service discovery method (e.g. mDNS) as well
as the protocol used for LDevID/domain credential enrollment. The Owner
Service may offer an arbitrary amount of PKI protocols to the device. It
is RECOMMENDED to support EST as the enrollment protocol. The AOKI
variant is comprised of an ``AokiInitializationRequest`` HTTP request
from the device to the Owner Service, followed by enrollment via a PKI
protocol agreed upon by the Device and Owner Service. #### Protocol
description The initial step is the automatic discovery of the Owner
Service by the Device upon initial connection to the network. This is
not defined herein, a suitable candidate for local networks would be
mDNS with the service type ``_aoki._tcp.``.

The AOKI Initialization Request is an HTTP ``GET`` request from the
Device to the Ownership Service on the endpoint ``/aoki/init``.

   Note: Registering the .well-known URI scheme /.well-known/aoki should be considered.

The Initialization request SHALL be made via TLS with client
authentication and the Device MUST use its IDevID as the certificate for
TLS client authentication. As the Device is generally not provisioned
with a TLS truststore at this point, it MAY provisionally trust the
Owner Service TLS server certificate.

Given a successful TLS handshake, the Owner Service now verifies that it
trusts the provided IDevID - for example by means of a Truststore
including the IDevID issuer. Additionally, it checks whether it is in
posession of a DevOwnerID certificate valid for this IDevID. If both
conditions are met and the Owner Service approves enrollment attempts
from this device, it replies with a HTTP 200 OK status and as content a
JSON message of the following format:

.. code:: json

   {
       "aoki-init": {
           "version": "1.0",
           "owner-id-cert": "----- BEGIN CERTIFICATE ----- ..."
           "tls-truststore": "----- BEGIN CERTIFICATE ----- ..."
           "enrollment-info": {
               "protocols": [
                   {
                       "protocol":"EST",
                       "url":"https://localhost/.well-known/est/domain/domaincredential/"
                   }
               ]
           }
       }
   }

JSON field descriptions
~~~~~~~~~~~~~~~~~~~~~~~

``version``: The version of the ``aoki`` protocol used by the Owner
Service. This number follows semantic versioning, i.e. clients SHOULD
expect breaking changes only if the major version is increased (``2.x``)

``owner-id-cert``: The DevOwnerID public key certificate corresponding
to the Device IDevID, as a PEM-encoded string.

``tls-truststore``: The TLS server certificate(s) the Device can trust for onboarding and
enrollment operations, as concatenated PEM-encoded string. The included
certificates SHALL include the TLS certificate used by the Owner Service
TLS server for this Initialization Request.

``enrollment-info``: Contains information regarding the device enrollment. Currently, only
``protocols`` is defined, though an Owner Service MAY include additional
application-domain specific fields.

``protocols``: A list of objects
defining the enrollment PKI protocols supported by the Owner Service.
The Device MAY freely choose any of the available protocols. A protocol
is defined by an object that contains at leasts the string ``protocol``.
Additional protocol-specific fields MAY be added, e.g. ``url``.

``protocol``: The name of the enrollment protocol as a string. ``url``:
The URL of the enrollment endpoint. REQUIRED for EST and CMP protocols.

Signature
~~~~~~~~~

After serializing the JSON response, the server signs the content bytes
of the response using the DevOwnerID private key. The Base64-encoded
signature bytes MUST be included as an ``AOKI-Signature`` HTTP header.
The OID dotted string of the used signature algorithm SHALL be included
as the ``AOKI-Signature-Algorithm`` HTTP header.

Failures and errors
~~~~~~~~~~~~~~~~~~~

If the Owner Service does not wish to accept the device or encounters an
error, it SHALL reply with an appropriate HTTP error status of 400 or
higher. It MAY include a human-readable representation of the error that
occured as content. The ``AOKI-Signature`` headers MUST NOT be included.

Initialization Request response handling by the Device
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the Device receives the response, it SHOULD first ascertain that
the response has HTTP status ``200 OK`` and that the response content is
a valid JSON object conforming to the format defined above. Furthermore,
it SHALL ensure the ``AOKI-Signature`` headers are present.

The Device is now expected to verify the provided DevOwnerID from the
``owner-id-cert`` field against the Owner Truststore the device has been
provisioned with. In case the Device has been onboarded before, it is
RECOMMENDED the device only accept DevOwnerIDs either equal to or issued
by the DevOwnerID used for the previous onboarding process; this is to
prevent previous device owners from onboarding the Device without the
consent of the current Owner.

Given the Device trusts the provided DevOwnerID, it SHALL verify the
provided Owner Signature in the ``AOKI-Signature`` header matches the
received content. If the signature is verified sucessfully, the Device
SHOULD parse the ``tls-truststore`` field and verify the TLS server
certificate used by the Owner Service is included in the truststore.
Once the TLS connection is verified, the Device MAY trust the Owner
Service and proceed to enrollment via e.g. EST.

AOKI Zero-Touch Device Onboarding via CMP
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The core functionality of AOKI - particularly mutual
authentication using IDevIDs and DevOwnerIDs - is alternatively implemented within a (lightweight)
Certificate Management Protocol (CMP) profile.

Compared to AOKI Mutual TLS Onboarding with flexible enrollment, this
offers the advantage of not relying on mutual TLS support and
potentially allows for onboarding in a single request/response cycle.
Furthermore, no AOKI-specific HTTP message protocol is required.
Disadvantages are all peers having to support the complex profiles
defined as part of CMP and no option of using enrollment protocols other
than CMP. An AOKI-specific implementation to verify DevOwnerIDs against
an IDevID is still required both for the Device and Owner Service.

This method is based on the CMP Initialization Request (IR) and
Initialization Response (IP) message types. Signature-based message
protection MUST be used. The Device SHALL use the IDevID as the CMP
protection certificate for the IR. The IDevID and its chain are included
in the ``extraCerts`` field. The Owner Service SHALL use the DevOwnerID
as the CMP protection certificate for the IP. In the event of successful
LDevID issuance, both the chain of the issued certificate and the
DevOwnerID certificate with its chain are included in the ``extraCerts``
field. Custom handling is required to separately extract the DevOwnerID
chain and LDevID chains from ``extraCerts``, which is unordered and MAY
contain other certificates unrelated to AOKI onboarding.

Implementation Notes
~~~~~~~~~~~~~~~~~~~~

The URL is ``/.well-known/cmp/initialization/.aoki`` in the PoC.
It would make sense to change this to ``/.well-known/cmp/p/.aoki/initialization`` in the future.
The DevOwnerID (CMP sender and signer) is the first certificate returned in the ``extraCerts`` field of the IP.
