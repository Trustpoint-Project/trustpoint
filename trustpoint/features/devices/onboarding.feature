@requirement.F_001
@capability.devices
@capability.onboarding
@allure.label.epic:Devices
@allure.label.suite:Onboarding
Feature: Device onboarding entry points
  Trustpoint exposes operator-driven onboarding for industrial devices.
  Legacy NTEU identity CRUD wording is replaced by current device/onboarding terminology.

  Scenario: Administrator can open the onboarding device form
    Given the admin user is logged into Trustpoint
    When the admin opens the onboarding device creation page
    Then the response status code is 200
    And the onboarding form contains a protocol selector
