@requirement.R_010
@requirement.R_011
@capability.api
@capability.enrollment
@allure.label.epic:API
@allure.label.suite:Enrollment_Endpoints
Feature: Enrollment protocol routing
  CMP and EST protocol endpoints are registered in the Trustpoint application.
  Wire-level protocol interoperability remains covered by the dedicated integration layer.

  Scenario Outline: Enrollment endpoint is registered
    Given the "<protocol>" protocol endpoint is registered
    Then the "<protocol>" route resolves to a Trustpoint view

    Examples:
      | protocol |
      | CMP      |
      | EST      |
