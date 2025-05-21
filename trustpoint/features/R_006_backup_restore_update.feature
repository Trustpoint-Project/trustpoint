Feature: Backup, Restore, and Update Mechanisms
  Ensure system resilience through robust backup, restoration, and update features.

  Background:
    Given the admin user is logged into TPC_Web

  Scenario Outline: Verifying the backup mechanism
    When the admin initiates a system backup
    Then the system confirms the backup process completes successfully
    And the backup file <backup_file> is retrievable and valid

    Examples:
      | backup_file     |
      | backup_20250128 |

  Scenario Outline: Verifying the restoration mechanism
    When the admin uploads a backup file <backup_file>
    Then the system restores the data successfully
    And the restored data is consistent with the backup file contents

    Examples:
      | backup_file     |
      | backup_20250128 |

  Scenario: Verifying the system update mechanism
    When the admin triggers a system update
    Then the system downloads and applies the update
    And the system verifies the integrity and functionality post-update
