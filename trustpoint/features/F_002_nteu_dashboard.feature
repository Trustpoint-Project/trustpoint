Feature: NTEU Dashboard
  NTEU must be able to log in to the TPC_Web app and check the charts and tables related to device, certificates, notification and issuing CA to monitor their status and expiration dates.

  Background:
    Given the TPC_Web application is running

  Scenario: Viewing the charts and table
    Given the NTEU log-in
    When the NTEU navigates to dashboard page
    Then 4 panels with title Certificates, Expiring Certificates, Devices and Issuing CAs should be visible
    And a notification table should be displayed
    And 3 chart tabs named, Device, Certificate and CA should be visible