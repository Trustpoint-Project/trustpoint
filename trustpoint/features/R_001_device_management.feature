@allure.label.epic:Features
@allure.label.suite:R_001_Manage_devices_via_TPC_Web
@allure.label.package:R_001_Manage_devices_via_TPC_Web
Feature: Manage devices via TPC_Web
  As an admin user
  I want to create, view, edit, and delete devices
  So that I can manage trusted devices effectively through the web interface.

  Background:
    Given the admin user is logged into TPC_Web
    And a domain with a name "trustpoint_test" exist

  Scenario Outline: Add a new device without domain credential onboarding
    When the admin navigates to the "Add Device" page
    And the admin fills in the device details with <name>, <serial_number> and "trustpoint_test"
    And the admin clicks on "Create Device"
    Then the system should display a confirmation page
    And the new device with <name>, <serial_number> and domain name "trustpoint_test" should appear in the device list

    Examples:
      | name            | serial_number |
      | Suction-Pads    | GC538K0DG7MW  |
      | Vacuum-Ejectors | 90OI4GL6RMNO  |

  Scenario Outline: Delete an existing device
    Given the device <name> with <serial_number> exists
    When the admin navigates to the "device list" page
    And the admin deletes the device with the name <name>
    Then the system should display a confirmation message stating "Successfully deleted"
    And the device <name> should no longer appear in the device list

    Examples:
      | name            | serial_number |
      | Suction-Pads    | GC538K0DG7MW  |
      | Vacuum-Ejectors | 90OI4GL6RMNO  |

  Scenario: Handle non-existent devices
    When the admin attempts to view the details of a non-existent device "NonExistentID"
    Then the system should display an error message
