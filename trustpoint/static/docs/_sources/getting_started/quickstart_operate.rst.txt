.. _quickstart-operation-guide:

Quickstart Operation Guide
==========================

This guide provides instructions for operating Trustpoint, including setting up an Issuing CA, a Domain, and adding a Device to manage its digital identity.

Setup an Issuing CA
-------------------
An Issuing Certificate Authority (CA) is central to managing certificates for your devices. Follow these steps to create and configure an Issuing CA in Trustpoint.

1. **Access the Trustpoint Web Interface**

   Open your browser and navigate to `https://localhost`. Use the default login credentials (`admin:testing321`) to access the Trustpoint interface.

2. **Navigate to Add new Issuing CAs**

   - From the main menu, click on **PKI** then **Issuing CAs**.
   - Click on **Add new Issuing CA**.
   - Click on **Import From PKCS#12 File** or **Import From Separate Key and Certificate Files**

3. **Configure Issuing CA Details**

   * When you click on **Import From PKCS#12 File**

     * Fill in the required fields:

       - **Unique Name**: Provide a unique name for your Issuing CA (e.g., `MyIssuingCA`).
       - **PKCS#12 File (.p12, .pfx)**: Select and upload a file
       - **[Optional] PKCS#12 password**: If your PKCS#12 is password protected type your password to import.

   * When you click on **Import From Separate Key and Certificate Files**

     * Fill in the required fields:

       - **Unique Name**: Provide a unique name for your Issuing CA (e.g., `MyIssuingCA`).
       - **Private Key File (.key, .pem)**: Select and upload a file
       - **[Optional] Private Key password**: If your PKCS#12 is password protected type your password to import.
       - **Issuing  CA Certificate (.cer, .der, .pem, .p7b, .p7c)**: Select and upload a file
       - **[Optional] Certificate Chain (.pem, .p7b, .p7c)**: If you have certificate chain.

   Click **Add New Issuing CA** to create the Issuing CA.

.. admonition:: Create a Self-Signed CA Certificate with OpenSSL
   :class: tip

   To create a self-signed CA certificate as a P12 file using OpenSSL, follow these steps:

   .. code-block:: bash

       # Generate a private key
       openssl ecparam -genkey -name secp256r1 -out ca-key.pem

       # Create a self-signed certificate
       openssl req -x509 -new -nodes -key ca-key.pem -sha256 -days 1825 -out ca-cert.pem -subj "/C=DE/ST=BW/L=Freudenstadt/O=Trustpoint/CN=MyIssuingCA"

       # Create a P12 file containing the private key and the certificate
       openssl pkcs12 -export -out ca-cert.p12 -inkey ca-key.pem -in ca-cert.pem -name "MyIssuingCA"

   This example will generate a self-signed CA certificate (`ca-cert.pem`) and package it as a P12 file (`ca-cert.p12`).

   .. warning::

      This example is for demonstration purposes only. It is not recommended to use a self-signed CA in production environments.


Setup a Domain
--------------
Domains allow you to group devices under a specific management structure. A domain can only be assigned to one issuing CA.

1. **Navigate to Add new Domain**

   - From the main menu, click on **PKI** then **Domains**.
   - Click **Add new Domain**.

2. **Enter Domain Information**

   Provide the following details:

   - **Unique Name**: Assign a name to your domain (e.g., `ProductionLine1`).
   - **Issuing CA**: Select the Issuing CA that will be used to issue certificates for this domain.

   Click **Add New Domain** to create the domain.

   Your domain is now ready, and you can begin adding devices to it.

Setup a Device
--------------
Devices are the end nodes that will receive digital certificates. Follow these steps to add a device to your domain.

1. **Navigate to Add Device**

   - From the main menu, click on **Devices**.
   - Click **Add new Device**.

2. **Enter Device Information**

   Fill in the required details:

   - **Device Name**: Provide a name for the device (e.g., `Sensor01`).
   - **Serial-Number**: Provide a serial number for the device (e.g., `1234567`).
   - **Domain**: Select the domain under which this device will be managed.
   - **Onboarding Configuration**: Check or uncheck `Domain Credential Onboarding`.
   - **PKI Configuration**: Based on `Domain Credential Onboarding`, you get options to select various PKI configuration, e.g., `Domain Credential Onboarding` unchecked and PKI configuration `Manual Download`

3. **Onboard device**

   - From the main menu, click on **Devices**.
   - Search your device in the table
   - Click **Start Onboarding**
   - Open a browser on your device
   - Visit the provided Download URL
   - Copy / Paste the Device ID and the provided OTP in the form
   - Click **Download credentials**
   - Click **Download PKCS12**

.. note::

      trustpoint offers different onboarding mechanisms. For more information see :ref:`onboarding-mechanisms`. `Trustpoint-Client <https://trustpoint-client.readthedocs.io>`_ is the easiest and preferred way of consuming Trustpoint.

.. admonition:: 🥳 CONGRATULATIONS!
   :class: tip

   You have now successfully set up an Issuing CA, created a domain, and onboarded a device to Trustpoint.
