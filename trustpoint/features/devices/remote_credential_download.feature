@requirement.R_013
@capability.devices
@capability.credentials
@allure.label.epic:Devices
@allure.label.suite:Remote_Credential_Download
Feature: Remote credential download
  An issued credential can be transferred to a remote device through a short-lived OTP workflow.

  Background:
    Given the Trustpoint web application is running

  Scenario: Administrator creates a one-time password
    Given an issued credential is successfully issued
    And the admin user is logged into Trustpoint
    When the admin visits the associated "Download on Device browser" view
    Then a one-time password is displayed which can be used to download the credential from a remote device

  Scenario: Correct OTP opens the download format page
    Given a correct one-time password
    When the user visits the "/devices/browser" endpoint and enters the OTP
    Then they will receive a page to select the format for the credential download

  Scenario: Incorrect OTP is rejected
    Given an incorrect one-time password
    When the user visits the "/devices/browser" endpoint and enters the OTP
    Then they will receive a warning saying the OTP is incorrect

  Scenario: Credential can be downloaded as encrypted PEM ZIP
    Given the user is on the credential download page
    And the download token is not yet expired
    When the user enters a password to encrypt the credential private key
    And selects a file format
    Then the credential will be downloaded to their browser in the requested format
