Feature: REST API interaction with TrustPoint
  As an API client
  I want to use the REST API to interact with TrustPoint
  So that I can programmatically manage digital identities.

  Background:
    Given an API client is authenticated

  Scenario Outline: Successfully create a new identity
    When the API client sends a POST request to "/api/identities" with the following payload:
      | name   | identifier   |
      | <name> | <identifier> |
    Then the API response should have a status code of 201
    And the response payload should include the created identity with:
      | name   | identifier   |
      | <name> | <identifier> |

    Examples:
      | name        | identifier |
      | Alice Smith | alice123   |
      | Bob Johnson | bob567     |

  Scenario Outline: Retrieve an existing identity
    Given the identity <identifier> exists
    When the API client sends a GET request to "/api/identities/<identifier>"
    Then the API response should have a status code of 200
    And the response payload should include the identity with:
      | identifier   | name   |
      | <identifier> | <name> |

    Examples:
      | identifier | name        |
      | alice123   | Alice Smith |
      | bob567     | Bob Johnson |

  Scenario Outline: Update an existing identity
    Given the identity <identifier> exists
    When the API client sends a PUT request to "/api/identities/<identifier>" with the following payload:
      | name       |
      | <new_name> |
    Then the API response should have a status code of 200
    And the response payload should include the updated identity with:
      | identifier   | name       |
      | <identifier> | <new_name> |

    Examples:
      | identifier | new_name     |
      | alice123   | Alice Cooper |
      | bob567     | Robert Jones |

  Scenario Outline: Delete an identity
    Given the identity <identifier> exists
    When the API client sends a DELETE request to "/api/identities/<identifier>"
    Then the API response should have a status code of 204
    And the identity <identifier> should no longer exist

    Examples:
      | identifier |
      | alice123   |
      | bob567     |

  Scenario: Attempt to access the API without authentication
    When the API client sends a GET request to "/api/identities" without authentication
    Then the API response should have a status code of 401
    And the response payload should include an error message stating "Unauthorized"

  Scenario Outline: Attempt to retrieve a non-existent identity
    When the API client sends a GET request to "/api/identities/<identifier>"
    Then the API response should have a status code of 404
    And the response payload should include an error message stating "Identity not found"

    Examples:
      | identifier |
      | unknown123 |
      | invalid567 |
