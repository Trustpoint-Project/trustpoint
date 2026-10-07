@requirement.R_007
@capability.system
@allure.label.epic:System
@allure.label.suite:Logging
Feature: System log access
  Authorized administrators can access Trustpoint log-management views.

  Scenario: Administrator opens the log file list
    Given the admin user is logged into Trustpoint
    When the admin opens the system log list
    Then the response status code is 200
