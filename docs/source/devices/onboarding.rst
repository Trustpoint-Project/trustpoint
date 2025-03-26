.. _onboarding-mechanisms:

=====================
Onboarding Mechanisms
=====================

This document outlines the different mechanisms available to onboard devices to Trustpoint,
including user-driven and automated methods.
These methods aim to streamline the process of issuing initial certificates (domain credentials)
that are used for secure device authentication with Trustpoint.

--------
Overview
--------

Trustpoint provides multiple ways to onboard a device.
Currently, the primary onboarding mechanism is user-driven,
with zero-touch onboarding being a future enhancement.
The following sections provide detailed information on each of these methods.

Onboarding a device to Trustpoint involves issuing a domain credential,
which allows the device to securely authenticate with Trustpoint.
There are two categories of onboarding available: user-driven onboarding and zero-touch onboarding.

-------------
No Onboarding
-------------

In certain industrial environments, especially those with air-gapped systems,
legacy devices, or extremely restrictive policies,
onboarding devices to Trustpoint may not always be feasible or necessary.

In these cases, devices may continue to operate without a domain credential managed by Trustpoint.
However, this approach is discouraged as it introduces security risks
and limits the device’s ability to participate in secure,
authenticated communication within the industrial network.

Trustpoint aims to reduce the need for "No Onboarding" scenarios by providing flexible onboarding methods
and supporting various industrial standards.
However, it acknowledges that in specific edge cases,
operating without an onboarding process may still occur.

----------------------
User-Driven Onboarding
----------------------

User-driven onboarding is the primary method available for onboarding devices to Trustpoint.
This method offers several options, depending on the user's preferences and available resources.

^^^^^^^^^^^^^^
Authentication
^^^^^^^^^^^^^^

To initially secure the client's request for a domain credential, various methods can be used depending on the onboarding:
 - **IDevID onboarding**: EST (WIP) and CMP both support an initial onboarding with the IDevID on the device. To do this, the initial request (for CMP an initialization request [ir]; for EST a /simpleenroll) must be signed with the IDevID.
 - **Shared secret**: Onboard a new device using CMP and a shared secret.
 - **Password**: Onboard a new device with EST protocol using a username and password
 - **One Time Password (OTP)**: Browser onboarding can be carried out using a one-time password

^^^^^^^^^^^^^^^^^^^^
Using the device CLI
^^^^^^^^^^^^^^^^^^^^

Users can also onboard their device manually by executing commands on the device command line interface (CLI).

How It Works:

- A new device with one of the the following options:
    - **:ref:`CMP` with shared secret onboarding**
    - **:ref:`CMP` with IDevID onboarding**
    - **:ref:`EST` with username and password onboarding** (WIP)
    - **:ref:`EST` with IDevID onboarding** (WIP)
- In **Devices** click **Manage** on the new device
- Click **Help - Issue New Credentials**
- Copy the provided (OpenSSL) commands to your clipboard and execute it on the device
- Upon successful submission, the device is issued a domain credential for authentication.

Requirements:

- A Linux machine with access to the command line.
- Necessary permissions.
- A connection to communicate with Trustpoint services.

""""""""""""""""""""""""""""""""""""""""""""""""""""
Example for :ref:`CMP` with shared secret onboarding
""""""""""""""""""""""""""""""""""""""""""""""""""""

This approach allows a device to obtain a domain credential from Trustpoint using the CMP protocol and a shared secret for authentication. It is a commonly used method when no initial identity certificate (IDevID) is available on the device.

.. note::

        The following commands are provided by Trustpoint in Devices > Manage > Help Issue New Credentials

The first step is to generate a key pair for the domain credential that will be requested from Trustpoint:

.. code-block:: bash

    openssl genrsa -out domain_credential_key.pem 2048

This will create a private key file named ``domain_credential_key.pem`` for the domain credential.

Next, use the CMP protocol with a shared secret to request the domain credential certificate from Trustpoint:

.. code-block:: bash

    openssl cmp \
    -cmd ir \
    -implicit_confirm \
    -server http://127.0.0.1:8000/.well-known/cmp/initialization/custom_domain/ \
    -ref 11 \
    -secret pass:None \
    -subject "/CN=Trustpoint Domain Credential" \
    -newkey domain_credential_key.pem \
    -certout cert.pem \
    -chainout chain.pem

Explanation of the Key Parameters:

- ``-cmd ir``: Initialization Request to obtain a new certificate.
- ``-implicit_confirm``: Enables implicit confirmation to finalize the certificate enrollment.
- ``-server``: The URL of the Trustpoint CMP endpoint. Replace this with the actual server URL in your setup.
- ``-ref 11``: Reference identifier provided during device registration.
- ``-secret pass:None``: The shared secret for onboarding. Replace ``None`` with the actual secret provided by Trustpoint.
- ``-subject "/CN=Trustpoint Domain Credential"``: The subject name for the domain credential certificate.
- ``-newkey domain_credential_key.pem``: The key pair generated earlier is used for the certificate request.
- ``-certout cert.pem``: The resulting certificate will be saved to ``cert.pem``.
- ``-chainout chain.pem``: The certificate chain will be saved to ``chain.pem``.

Upon successful execution, the device will receive its domain credential certificate,
enabling secure authentication with Trustpoint.

^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Using the Trustpoint Client (Work in Progress)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Trustpoint provides a user-friendly client application that simplifies the onboarding process. The Trustpoint client is available at `Trustpoint Client GitHub <https://github.com/TrustPoint-Project/trustpoint-client>`_. This method is recommended for users who prefer a guided approach to onboarding.

How It Works:

- A new device with the onboarding protocol **Trustpoint client** is added to Trustpoint
- In **Devices** click **Start Onboarding** on the new device
- Copy the provided command to your clipboard and execute it on the device
- The device is onboarded
- During the process, an initial certificate is issued, enabling secure device authentication with Trustpoint.

Requirements:

- Access to the Device.
- Python 3.12 or greater on device.
- Trustpoint-Client installed on the device (via `pip install trustpoint-client`).
- A connection to communicate with Trustpoint services.

----------------------------------------
Zero-Touch Onboarding (Work in Progress)
----------------------------------------

Trustpoint is actively developing a zero-touch onboarding feature. This mechanism will allow fully automated onboarding without any user intervention, simplifying the process even further. Zero-touch onboarding is designed for use in environments where many devices need to be onboarded without manual effort, providing a scalable solution for large deployments.

How It Works:

- Devices are pre-configured with Trustpoint information before deployment.
- Upon connecting to the network, the device automatically requests and receives an initial certificate, completing the onboarding process without user interaction.

Requirements:

- Network infrastructure to support automated onboarding.


The Trustpoint beta release contains zero touch onboarding functionality for demonstration purposes only,
based on the AOKI (Automated Onboarding Key Infrastructure) protocol.
This is a simple protocol that uses mDNS to discover the Trustpoint server
and then uses a simple REST API for mutual trust establishment.
Afterwards, the device is in possession of a OTP it can use for LDevID provisioning via standard CMP.
Before the device can be onboarded, it must possess a valid IDevID (Initial device identifier per IEEE 802.1AR) certificate.
The Trustpoint needs to have a valid trust anchor certificate for the device's IDevID certificate added as a Truststore.
It also needs an ownership certificate, which is issued by the manufacturer
and verified by the device to authenticate the Trustpoint.

This feature is not intended for production use.

^^^^^^
How to
^^^^^^

1. **(Optional) Generate IDevID and ownership certificates**

2. **(Optional) Add IDevID to the device Trustpoint client**
    Install the Trustpoint Client to the device. An example IDevID is provided in the ``demo-data`` directory.

3. **Add Truststores in Trustpoint**
    Two Truststores with arbitrary names need to be added, one containing the certificate chain of the IDevID and one containing the certificate chain of the ownership certificate.
    Demo certificates are provided in the ``tests/data/aoki_zero_touch`` directory.

4. **Configure mDNS address**
    In ``settings.py`` set ``ADVERSISED_HOST`` to the Trustpoint server IP address as reachable by the device.

5. **Onboard the device**
    Execute ``trustpoint-client provision zero-touch`` command on the client to onboard the device.


