@allure.label.owner:Aircoookie
@allure.label.epic: R_013 Remote Credential Download
@allure.label.suite: R_013 Remote Credential Download
@allure.label.package: R_013 Remote Credential Download
@fixture.r013.setup
Feature: R_013 Remote Credential Download
  The system must allow users to securely download an issued credential
  from a remote device without requiring user authentication.
  Instead, a one-time password (OTP) should be used to authorize the download.

  Background:
    Given the TPC_Web application is running

  @critical
  Scenario: Admin creates one time password
    Given an issued credential is successfully issued
    And the admin user is logged into TPC_Web
    When the admin visits the associated "Download on Device browser" view
    Then a one-time password is displayed which can be used to download the credential from a remote device

  @normal
  Scenario: User enters one time password correctly
    Given a correct one-time password
    When the user visits the "/devices/browser" endpoint and enters the OTP
    Then they will receive a page to select the format for the credential download

  @minor
  Scenario: User enters one time password incorrectly
    Given an incorrect one-time password
    When the user visits the "/devices/browser" endpoint and enters the OTP
    Then they will receive a warning saying the OTP is incorrect

  @critical
  Scenario: User downloads credential on remote device browser
    Given the user is on the credential download page
    And the download token is not yet expired
    When the user enters a password to encrypt the credential private key
    And selects a file format
    Then the credential will be downloaded to their browser in the requested format
