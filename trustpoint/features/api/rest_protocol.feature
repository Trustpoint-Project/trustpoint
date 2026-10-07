@requirement.R_004
@capability.api
@capability.enrollment
@allure.label.epic:API
@allure.label.suite:REST_Enrollment_Protocol
Feature: REST certificate enrollment protocol routing
  Trustpoint exposes dedicated REST certificate enrollment and re-enrollment routes.

  Scenario Outline: REST certificate operation is registered
    Given the REST certificate "<operation>" endpoint is registered
    Then the REST certificate route resolves to a Trustpoint view

    Examples:
      | operation |
      | enroll    |
      | reenroll  |
