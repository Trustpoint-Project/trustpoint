@capability.pki
@capability.ra
@allure.label.epic:PKI
@allure.label.suite:Registration_Authority
Feature: Registration Authority modes
  Trustpoint can operate as a Registration Authority in front of an external PKI.

  Background:
    Given the admin user is logged into Trustpoint

  Scenario: Configure an EST Registration Authority
    Given a remote EST RA named "behave-est-ra" exists
    Then the CA mode is "REMOTE_EST_RA"
    When that authority is assigned to domain "est-ra-domain"
    Then domain "est-ra-domain" uses that authority

  Scenario: Configure a CMP Registration Authority
    Given a remote CMP RA named "behave-cmp-ra" exists
    Then the CA mode is "REMOTE_CMP_RA"
    When that authority is assigned to domain "cmp-ra-domain"
    Then domain "cmp-ra-domain" uses that authority
