@requirement.R_001
@capability.devices
@allure.label.epic:Devices
@allure.label.suite:Device_Management
Feature: Device management
  As an administrator
  I want to manage industrial devices
  So that machine identities can be managed consistently.

  Background:
    Given the admin user is logged into Trustpoint
    And a domain named "behave-domain" exists

  @critical
  Scenario: Create a no-onboarding device
    When the admin creates a no-onboarding device named "behave-device" with serial number "SN-1001" in domain "behave-domain"
    Then the response status code is 200
    And a device named "behave-device" with serial number "SN-1001" exists
    And the device "behave-device" belongs to domain "behave-domain"
    And the device "behave-device" uses no-onboarding
    And the device "behave-device" has PKI protocol "MANUAL" enabled

  @normal
  Scenario: Create a device without a domain
    When the admin creates a no-onboarding device named "device-without-domain" with serial number "SN-1002" without a domain
    Then the response status code is 200
    And a device named "device-without-domain" with serial number "SN-1002" exists
    And the device "device-without-domain" has no domain assigned

  @normal
  Scenario: Create a device without a serial number
    When the admin creates a no-onboarding device named "device-without-serial" without a serial number in domain "behave-domain"
    Then the response status code is 200
    And a device named "device-without-serial" exists
    And the device "device-without-serial" has an empty serial number

  @critical
  Scenario: Create a no-onboarding device using CMP shared-secret authentication
    When the admin creates a no-onboarding device named "cmp-device" using PKI protocol "CMP_SHARED_SECRET" in domain "behave-domain"
    Then the response status code is 200
    And a device named "cmp-device" exists
    And the device "cmp-device" has PKI protocol "CMP_SHARED_SECRET" enabled
    And a CMP shared secret was generated for device "cmp-device"

  @critical
  Scenario: Create a no-onboarding device using EST username and password authentication
    When the admin creates a no-onboarding device named "est-device" using PKI protocol "EST_USERNAME_PASSWORD" in domain "behave-domain"
    Then the response status code is 200
    And a device named "est-device" exists
    And the device "est-device" has PKI protocol "EST_USERNAME_PASSWORD" enabled
    And an EST or REST password was generated for device "est-device"

  @critical
  Scenario: Create a no-onboarding device using REST username and password authentication
    When the admin creates a no-onboarding device named "rest-device" using PKI protocol "REST_USERNAME_PASSWORD" in domain "behave-domain"
    Then the response status code is 200
    And a device named "rest-device" exists
    And the device "rest-device" has PKI protocol "REST_USERNAME_PASSWORD" enabled
    And an EST or REST password was generated for device "rest-device"

  @normal
  Scenario: Create a device with multiple no-onboarding PKI protocols
    When the admin creates a no-onboarding device named "multi-protocol-device" with the following PKI protocols in domain "behave-domain":
      | protocol              |
      | CMP_SHARED_SECRET     |
      | EST_USERNAME_PASSWORD |
      | MANUAL                |
      | REST_USERNAME_PASSWORD |
    Then the response status code is 200
    And a device named "multi-protocol-device" exists
    And the device "multi-protocol-device" has PKI protocol "CMP_SHARED_SECRET" enabled
    And the device "multi-protocol-device" has PKI protocol "EST_USERNAME_PASSWORD" enabled
    And the device "multi-protocol-device" has PKI protocol "MANUAL" enabled
    And the device "multi-protocol-device" has PKI protocol "REST_USERNAME_PASSWORD" enabled
    And a CMP shared secret was generated for device "multi-protocol-device"
    And an EST or REST password was generated for device "multi-protocol-device"

  @security
  Scenario: Reject a duplicate device name
    Given a device named "duplicate-device" exists in domain "behave-domain"
    When the admin attempts to create another no-onboarding device named "duplicate-device" in domain "behave-domain"
    Then the response status code is 200
    And exactly one device named "duplicate-device" exists
    And the device creation form reports that the device name already exists

  @normal
  Scenario: Generate a stable RFC 4122 UUID for a device
    When the admin creates a no-onboarding device named "uuid-device" with serial number "SN-UUID-1" in domain "behave-domain"
    Then the response status code is 200
    And the device "uuid-device" has an RFC 4122 version 4 UUID

  @normal
  Scenario: Device UUIDs are unique
    Given a device named "uuid-device-one" exists in domain "behave-domain"
    And a device named "uuid-device-two" exists in domain "behave-domain"
    Then the devices "uuid-device-one" and "uuid-device-two" have different UUIDs

  @normal
  Scenario: List an existing device
    Given a device named "listed-device" exists in domain "behave-domain"
    When the admin opens the device list
    Then the response status code is 200
    And the device list contains "listed-device"

  @critical
  Scenario: Delete an existing device
    Given a device named "delete-device" exists in domain "behave-domain"
    When the admin deletes that device
    Then the response status code is 200
    And the device "delete-device" no longer exists

  @minor
  Scenario: Handle a request for a non-existent device
    When the admin opens non-existent device id 999999
    Then the response status code is 404