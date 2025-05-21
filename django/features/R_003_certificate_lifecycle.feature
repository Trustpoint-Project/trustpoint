Feature: Certificate lifecycle management via TPC_Web
  As an admin user
  I want to manage certificates across their lifecycle
  So that I can ensure their validity and revoke them when necessary.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Successfully renew a certificate
    Given the certificate <certificate_id> exists and is close to expiration
    When the admin navigates to the certificate management page for <certificate_id>
    And the admin initiates the certificate renewal process
    Then the system should display a confirmation message
    And the certificate <certificate_id> should have an updated expiration date

    Examples:
      | certificate_id |
      | CERT1234       |
      | CERT5678       |

  Scenario Outline: Successfully revoke a certificate
    Given the certificate <certificate_id> exists and is active
    When the admin navigates to the certificate management page for <certificate_id>
    And the admin initiates the certificate revocation process
    Then the system should display a confirmation message
    And the certificate <certificate_id> should have a status of "revoked"

    Examples:
      | certificate_id |
      | CERT9101       |
      | CERT1121       |

  Scenario: Attempt to renew a non-existent certificate
    When the admin attempts to <renew> a non-existent certificate "NONEXISTENT"
    Then the system should display an error message stating "Certificate not found"

  Scenario: Attempt to revoke a non-existent certificate
    When the admin attempts to <revoke> a non-existent certificate "NONEXISTENT"
    Then the system should display an error message stating "Certificate not found"

  Scenario Outline: Attempt to renew a revoked certificate
    Given the certificate <certificate_id> exists and is revoked
    When the admin attempts to renew the certificate <certificate_id>
    Then the system should display an error message stating "Certificate renewal not allowed for revoked certificates"

    Examples:
      | certificate_id |
      | CERT3131       |
      | CERT4151       |

  Scenario Outline: Attempt to revoke an already revoked certificate
    Given the certificate <certificate_id> exists and is revoked
    When the admin attempts to revoke the certificate <certificate_id>
    Then the system should display an error message stating "Certificate is already revoked"

    Examples:
      | certificate_id |
      | CERT6161       |
      | CERT7171       |
