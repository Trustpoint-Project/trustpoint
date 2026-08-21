.. _inspect-certificate:

Inspect a Certificate with OpenSSL
==================================

After Trustpoint issues a certificate, use OpenSSL to inspect the public
certificate before deploying it. This confirms which identity was certified,
which CA issued it, how long it is valid, and which cryptographic algorithms it
uses.

Prepare a PEM certificate
-------------------------

The examples below expect a PEM-encoded certificate named
``certificate.pem``. If you downloaded a PKCS#12 credential from Trustpoint,
extract only the end-entity certificate first:

.. code-block:: bash

   openssl pkcs12 -in device-credentials.p12 -clcerts -nokeys -out certificate.pem

OpenSSL prompts for the PKCS#12 import password. The ``-nokeys`` option keeps
the private key out of the output file. Do not share the original PKCS#12 file
or any exported private key.

Print the certificate
---------------------

Run:

.. code-block:: bash

   openssl x509 -in certificate.pem -text -noout

The command parses the certificate locally and prints a human-readable view.
It does not contact Trustpoint or change the certificate.

Read the important fields
-------------------------

Look for these fields in the output:

``Subject``
   The identity bound to the certificate. For a Trustpoint-issued device or
   application credential, check that attributes such as the common name,
   domain component, and serial number identify the intended device or
   application. See :ref:`issued_cert_defaults` for Trustpoint's default
   certificate subjects.

``Issuer``
   The CA that signed the certificate. It should match the issuing CA selected
   for the Trustpoint domain. ``Subject`` and ``Issuer`` can be identical for a
   self-signed CA certificate, but they normally differ for device and
   application certificates.

``Validity``
   The ``Not Before`` and ``Not After`` timestamps define the period in which
   the certificate is valid. Confirm that the current time falls inside this
   interval and that the lifetime matches the applicable Trustpoint certificate
   profile. OpenSSL displays these timestamps in UTC.

``Public Key Algorithm``
   The type of public key contained in the certificate, such as RSA or EC.
   Inspect the following lines for details such as the RSA key size or elliptic
   curve, and compare them with the Trustpoint certificate profile.

``Signature Algorithm``
   The algorithm the issuing CA used to sign the certificate, such as
   ``sha256WithRSAEncryption`` or ``ecdsa-with-SHA256``. This is separate from
   the subject's public-key algorithm: the issuer's signing key determines the
   certificate signature.

For a compact identity and lifetime check, print only the corresponding
fields:

.. code-block:: bash

   openssl x509 -in certificate.pem -noout -subject -issuer -dates

Inspection confirms the certificate's encoded contents; it does not prove that
the certificate chains to a trusted CA or that it has not been revoked. Perform
the trust-chain and revocation checks required by the target application before
deployment.
