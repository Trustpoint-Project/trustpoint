@requirement.R_102
@capability.pki
@allure.label.epic:PKI
@allure.label.suite:Certificate_Profiles
Feature: Certificate profile management
  Certificate profiles are a protected PKI capability in the current Trustpoint model.

  Scenario: Administrator can open certificate profiles
    Given the admin user is logged into Trustpoint
    When the admin opens the certificate profile list
    Then the response status code is 200
