Feature: Add and delete new Issuing CAs
  The system must provide a way to add and delete new issuing CAs.

  Background:
    Given the admin user is logged into TPC_Web
    And the admin is on the "pki/issuing-cas" webpage

  Scenario: Add a new issuing CA by uploading a valid PKCS12 file
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From PKCS#12 File"
    Then the system should display a form page where a file can be uploaded
    When the admin uploads a valid PKCS12 issuing CA file
    And the admin clicks the "Add new issuing CA" button
    Then the system should display a confirmation message stating "Successfully added Issuing CA"
    Then the added issuing CA "test" "appears" in the list of available CAs


  Scenario: Add a new issuing CA by uploading a broken PKCS12 file
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From PKCS#12 File"
    Then the system should display a form page where a file can be uploaded
    When the admin uploads a broken PKCS12 issuing CA file
    And the admin clicks the "Add new issuing CA" button
    Then the response payload should include an error message stating "Failed to parse"
    And the added issuing CA "test" "does not appear" in the list of available CAs


  Scenario: Add a new issuing CA by uploading a duplicated PKCS12 file
    Given the issuing ca with pkcs12 file exist
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From PKCS#12 File"
    Then the system should display a form page where a file can be uploaded
    When the admin uploads a duplicated PKCS12 issuing CA file
    And the admin clicks the "Add new issuing CA" button
    Then the response payload should include an error message stating "UNIQUE constraint failed"
    And the added issuing CA "test" "appears" in the list of available CAs


  Scenario Outline: Add a new issuing CA by uploading valid key and certificate files
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From Separate Key and Certificate Files"
    Then the system should display a form page where a file can be uploaded
    When the key file of type <key_type> is "valid"
    And the certificate file of type <cert_type> is "valid"
    And the certificate file is "a CA certificate"
    And the certificate chain of type <cert_chain> is "valid"
    And the admin clicks the "Add new issuing CA" button
    Then the system should display a confirmation message stating "Successfully added Issuing CA"
    Then the added issuing CA "test" "appears" in the list of available CAs

    Examples:
      | key_type | cert_type | cert_chain |
      | .key     | .cer      | .pem       |
      | .key     | .der      | .p7b       |
      | .key     | .pem      | .p7c       |
      | .key     | .p7b      | .pem       |
      | .key     | .p7c      | .p7b       |
      | .pem     | .cer      | .p7c       |
      | .pem     | .der      | .pem       |
      | .pem     | .pem      | .p7b       |
      | .pem     | .p7b      | .p7c       |
      | .pem     | .p7c      | None       |


  Scenario Outline: Add a new issuing CA by uploading end entity certificates
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From Separate Key and Certificate Files"
    Then the system should display a form page where a file can be uploaded
    When the key file of type ".pem" is "valid"
    And the certificate file of type <cert_type> is "valid"
    And the certificate file is "an end entity certificate"
    And the certificate chain of type ".pem" is "valid"
    And the admin clicks the "Add new issuing CA" button
    Then the system should display an error message
    And the added issuing CA "test" "does not appear" in the list of available CAs

    Examples:
      | cert_type |
      | .cer      |
      | .der      |
      | .pem      |
      | .p7b      |
      | .p7c      |

  Scenario: Add a new issuing CA by uploading valid key and certificate files - Mismatched key and cert file
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From Separate Key and Certificate Files"
    Then the system should display a form page where a file can be uploaded
    When the key file of type ".pem" is "valid"
    And the certificate file of type ".pem" is "valid"
    When the key and the certificate file are not matching
    And the admin clicks the "Add new issuing CA" button
    Then the system should display an error message
    And the added issuing CA "test" "does not appear" in the list of available CAs

  Scenario: Add a new issuing CA by uploading valid key and certificate files but mismatching chain
    When the admin clicks on "Add new Issuing CA"
    Then the system should display multiple options to add a new issuing CA
    When the admin clicks on "Import From Separate Key and Certificate Files"
    Then the system should display a form page where a file can be uploaded
    When the key file of type ".pem" is "valid"
    And the certificate file of type ".pem" is "valid"
    And the certificate file is "a CA certificate"
    And the certificate chain of type ".pem" is "valid"
    And the certificate chain does not contain the issuer of the certificate file
    And the admin clicks the "Add new issuing CA" button
    Then the system should display an error message
    And the added issuing CA "test" "does not appear" in the list of available CAs

  Scenario: Delete an issuing CA
    Given there is an issuing CA with the unique name "test_CA"
    And the issuing CA with the unique name "test_CA" has no associated certificates
    And the issuing CA with the unique name "test_CA" has no assoociated domains
    When the admin clicks on the issuing CA with the unique name "test_CA"
    And the admin clicks on "delete"
    Then the system should display a confirmation dialog page
    And the admin clicks on "delete selected issuing CA"
    Then the system should display a confirmation message stating "Successfully deleted"
    Then the deleted issuing CA "test" "does not appear" in the list of available CAs
