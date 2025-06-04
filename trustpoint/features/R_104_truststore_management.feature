Feature: Manage truststores via TPC_Web
  As an admin user
  I want to create, view, edit, and delete truststores
  So that I can manage truststores effectively through the web interface.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Add a new truststore
    When the admin navigates to the "Add new Truststore" page
    And the admin fills in the truststore details with <name>, <intended_usage> and <file_type>
    And the admin clicks on "Add new Truststore"
    Then the system should display a confirmation message stating "Successfully created the Truststore"
    And the new truststore with <name> and <intended_usage> should appear in the truststore list
    Examples:
      | name         | intended_usage | file_type |
      | truststore_1 | IDevID         | .pem      |
      | truststore_2 | TLS            | .pem      |
      | truststore_3 | Generic        | .pem      |
      | truststore_4 | IDevID         | .pkcs7    |
      | truststore_5 | TLS            | .pkcs7    |
      | truststore_6 | Generic        | .pkcs7    |

  Scenario Outline: Delete an existing truststore
    Given a truststore <name> with <intended_usage> exist
    When the admin navigates to the "truststore list" page
    And the admin deletes the truststore with the name <name>
    Then the system should display a confirmation message stating "Successfully deleted"
    And the truststore <name> should no longer appear in the truststore list

    Examples:
      | name         | intended_usage |
      | truststore_1 | IDevID         |
      | truststore_2 | TLS            |
      | truststore_3 | Generic        |

  Scenario: Handle non-existent truststores
    When the admin attempts to view the details of a non-existent truststore "NonExistentID"
    Then the system should display an error message
