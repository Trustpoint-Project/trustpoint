Feature: Logging Capabilities
  The system must provide detailed and configurable logging for system events and actions.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Logging user actions
    When the admin performs an action <action>
    Then the system logs the action <action> with relevant details

    Examples:
      | action |
      | create |
      | update |
      | delete |

  Scenario Outline: Retrieving and filtering logs
    When the admin retrieves logs for the time range <time_range>
    Then the system displays logs within the <time_range>
    And logs can be filtered by <filter_criteria>

    Examples:
      | time_range    | filter_criteria |
      | last 24 hours | user            |
      | last 7 days   | event type      |

  Scenario Outline: Configuring logging settings
    When the admin modifies logging configuration to <log_level>
    Then the system applies the new logging configuration
    And logs reflect the new verbosity level <log_level>

    Examples:
      | log_level |
      | DEBUG     |
      | INFO      |
      | WARNING   |

  Scenario: Ensuring log storage and integrity
    When the system restarts
    Then previous logs are still accessible
    And unauthorized users cannot delete or modify logs
