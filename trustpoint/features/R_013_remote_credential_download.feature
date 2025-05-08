@fixture.r013.setup
@feature:Remote_Credential_Download               # Allure Feature label
Feature: Remote Credential Download
  The system must allow users to securely download an issued credential
  from a remote device without requiring user authentication.
  Instead, a one-time password (OTP) should be used to authorize the download.

  Background:
    Given the TPC_Web application is running

  @story:Generate_OTP                            # Allure Story label
  @severity:critical                             # Allure Severity label
  @testcase:TP-001                               # Allure Testcase ID
  Scenario: Admin creates one time password
    Given an issued credential is successfully issued
    And the admin user is logged into TPC_Web
    When the admin visits the associated "Download on Device browser" view
    Then a one-time password is displayed which can be used to download the credential from a remote device

  @story:Validate_OTP_Correct                     # Allure Story label
  @severity:normal
  @testcase:TP-002
  Scenario: User enters one time password correctly
    Given a correct one-time password
    When the user visits the "/devices/browser" endpoint and enters the OTP
    Then they will receive a page to select the format for the credential download

  @story:Validate_OTP_Incorrect                   # Allure Story label
  @severity:minor
  @testcase:TP-003
  Scenario: User enters one time password incorrectly
    Given an incorrect one-time password
    When the user visits the "/devices/browser" endpoint and enters the OTP
    Then they will receive a warning saying the OTP is incorrect

  @story:Download_Credential                      # Allure Story label
  @severity:critical
  @testcase:TP-004
  Scenario: User downloads credential on remote device browser
    Given the user is on the credential download page
    And the download token is not yet expired
    When the user enters a password to encrypt the credential private key
    And selects a file format
    Then the credential will be downloaded to their browser in the requested format
