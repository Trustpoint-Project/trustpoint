@requirement.R_004
@capability.api
@capability.security
@allure.label.epic:API
@allure.label.suite:Service_Account_Authentication
Feature: API service account authentication
  API-only integrations should use service accounts instead of interactive user credentials.

  Scenario: Service account obtains an access token
    Given an active service account credential exists
    When the service account requests an OAuth2 token with client credentials
    Then the response status code is 200
    And the token response contains an access token

  Scenario: Invalid service-account secret is rejected
    Given an active service account credential exists
    When the service account requests a token with an invalid secret
    Then the response is an authentication failure

  Scenario: Service accounts cannot use interactive web login
    Given an active service account credential exists
    Then the service account is not allowed to log into the web UI
