^^^^^
R_101
^^^^^

This testcase is related to requirement `R_101`_.

"""""""""
Test Idea
"""""""""

To verify that only devices with valid certificates can communicate, we will test the following scenarios:

#. Device with a Valid Certificate Can Communicate
    - A device is provisioned with a valid certificate.
    - The system allows the device to establish communication.

#. Device with an Expired Certificate is Denied
    - A device presents an expired certificate.
    - The system denies communication and logs the attempt.

#. Device with a Revoked Certificate is Denied
    - A certificate is revoked by the system administrator.
    - A device attempting to communicate with the revoked certificate is rejected.

#. Device with a Self-Signed or Untrusted Certificate is Denied
    - A device presents a self-signed certificate.
    - The system denies communication.

#. Device with a Tampered Certificate is Denied
    - A device presents a certificate with altered data.
    - The system detects the tampering and blocks communication.

#. Device Attempts Communication Without a Certificate
    - A device attempts to communicate without presenting any certificate.
    - The system rejects the request.

#. Logging of Authentication Failures
    - Every failed authentication attempt due to an invalid, expired, or revoked certificate is logged.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ./../../../../trustpoint/features/R_101_device_cert_validation.feature
   :language: gherkin

^^^^^
R_102
^^^^^

This testcase is related to requirement `R_102`_.

"""""""""
Test Idea
"""""""""

To verify that communication between machines is encrypted using the given algorithm, we will test the following scenarios:

#. Valid Encrypted Communication
    - Two machines establish a communication session.
    - The communication is encrypted using the specified encryption algorithm.
    - The system successfully verifies encryption.

#. Communication with No Encryption is Rejected
    - A machine attempts to communicate without encryption.
    - The system detects the unencrypted communication and blocks it.
    - The system logs the rejected attempt.

#. Communication Using an Unsupported Encryption Algorithm is Rejected
    - A machine attempts to use an encryption algorithm that is not approved.
    - The system rejects the communication.
    - The system logs the failed attempt.

#. Communication Using a Weak Encryption Algorithm is Rejected
    - A machine attempts to use a weak or deprecated encryption algorithm.
    - The system denies the communication.
    - The system logs the failure with a warning.

#. Communication is Encrypted with the Correct Key Exchange Mechanism
    - Two machines establish a secure session using the correct key exchange protocol.
    - The system verifies that the encryption is correctly applied.

#. Communication is Tamper-Resistant
    - A third party attempts to modify an encrypted message.
    - The system detects the tampering and terminates the connection.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ./../../../../trustpoint/features/R_102_encrypted_communication.feature
   :language: gherkin

^^^^^
R_103
^^^^^

This testcase is related to requirement `R_103`_.

"""""""""
Test Idea
"""""""""

To verify that administrators can configure security levels for different Trustpoint components, we will test the following scenarios:

#. Set Security Level for a Component
    - The admin selects a Trustpoint component.
    - The admin sets the security level to "High".
    - The system successfully applies and saves the security level.

#. Modify an Existing Security Level
    - The admin updates the security level of a component from "Medium" to "High".
    - The system correctly applies and reflects the change.

#. Invalid Security Level Input is Rejected
    - The admin attempts to set an invalid security level.
    - The system rejects the input and displays an error.

#. Security Level Persists After System Restart
    - The admin configures a security level for a component.
    - The system is restarted.
    - The security level remains correctly applied.

#. Security Level Affects System Behavior
    - A component with a high-security level enforces stricter access control.
    - A component with a low-security level has more lenient settings.
    - The system behaves accordingly.

#. Security Configuration is Logged
    - Every change to security levels is logged.
    - The log contains details such as timestamp, admin ID, and old/new security levels.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ./../../../../trustpoint/features/R_103_security_configuration.feature
   :language: gherkin

^^^^^
R_104
^^^^^

This testcase is related to requirement `R_104`_.

"""""""""
Test Idea
"""""""""

To verify that certificate template security is enforced properly, we will test the following scenarios:

#. Only Authorized Users Can Access Certificate Templates
    - A user with admin privileges accesses the certificate templates.
    - A regular user attempts to access certificate templates but is denied.

#. Secure Handling of Certificate Templates
    - A certificate template is created with restricted access.
    - The system prevents unauthorized modifications.
    - The system encrypts stored templates.

#. Modification of Certificate Templates
    - An admin updates a certificate template.
    - Unauthorized users attempt modifications but are denied.

#. Deletion Restrictions
    - Only authorized users can delete certificate templates.
    - Unauthorized users receive an error when attempting deletion.

#. Logging of Access and Modifications
    - The system logs every access and modification of certificate templates.

#. Secure Export of Certificate Templates
    - The system ensures that exported templates are encrypted.
    - Unauthorized export attempts are blocked.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ./../../../../trustpoint/features/R_104_certificate_template_security.feature
   :language: gherkin