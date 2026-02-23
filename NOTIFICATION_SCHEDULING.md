"""
Summary of Django-Q2 Notification Scheduling Implementation

This document describes how notifications are scheduled and executed cyclically using Django-Q2,
similar to the CRL generation workflow.

ARCHITECTURE OVERVIEW
====================

1. NotificationConfig Model (management/models/notifications.py)
   - Added `schedule_next_notification_check(cycle_interval_hours: int = 1)` method
   - Respects the global `enabled` flag
   - Uses Django-Q2's `schedule()` function to create one-off scheduled tasks
   - Logs scheduling events

2. Management Task (management/tasks.py)
   - `execute_all_notifications()` function runs via Django-Q2
   - Calls the `run_all_notifications` management command
   - Handles CommandError and general exceptions with logging

3. Management Commands
   
   a) init_notifications.py (initialization command)
      - Purpose: Initialize notification scheduling when starting the application
      - Usage: `python manage.py init_notifications [--interval-hours N]`
      - Should be run once after deployment or application startup
      - Respects the global notifications enabled/disabled setting
      - Default interval: 1 hour
      - Output: Confirms scheduling or indicates disabled notifications
   
   b) execute_all_notifications.py (scheduling command)
      - Purpose: Schedule the next notification check via Django-Q2
      - Usage: `python manage.py execute_all_notifications [--interval-hours N]`
      - Respects the global notifications enabled/disabled setting
      - Default interval: 1 hour
      - Output: Confirms scheduling or indicates disabled notifications
   
   c) run_all_notifications.py (execution command)
      - Purpose: Run all notification checks sequentially
      - Called by the Django-Q2 task during scheduled execution
      - Respects the global `enabled` flag before running
      - Runs these commands in order:
        1. trustpoint_setup_notifications
        2. check_system_health
        3. check_for_security_vulnerabilities
        4. check_certificate_validity
        5. check_issuing_ca_validity
        6. check_domain_issuing_ca
        7. check_non_onboarded_devices
        8. check_for_weak_signature_algorithms
        9. check_for_insufficient_key_length
        10. check_for_weak_ecc_curves
      - Tracks failed commands and reports them
      - Handles errors gracefully without stopping the entire execution

WORKFLOW
========

1. Application Startup (First Time Setup):
   $ python manage.py init_notifications --interval-hours 1
   - This initializes and schedules the first notification check to run in 1 hour
   - NotificationConfig.schedule_next_notification_check() is called
   - Django-Q2 stores the scheduled task in the ORM
   - Make sure Q Cluster is running: uv run trustpoint/manage.py qcluster

2. Django-Q2 Execution (Automatic - runs at scheduled time):
   - Q Cluster worker picks up the scheduled task
   - Executes: management.tasks.execute_all_notifications()
   - This calls `run_all_notifications` management command
   - All notification checks run sequentially
   - Results are logged to the logger

3. Automatic Rescheduling (After execution):
   - After all checks complete, manually reschedule the next cycle
   - This can be done via:
     a) Cron job: every hour run `python manage.py execute_all_notifications`
     b) Celery beat: configure a periodic task
     c) Manual: call `python manage.py execute_all_notifications` as needed

GETTING STARTED
===============

1. Start the Q Cluster (in a separate terminal):
   $ uv run trustpoint/manage.py qcluster
   - This keeps running and processes scheduled tasks

2. Initialize notification scheduling (in main terminal):
   $ uv run trustpoint/manage.py init_notifications --interval-hours 1
   - This schedules the first check to run in 1 hour

3. Check Q Cluster logs to see when tasks execute:
   - Look for: "Process-xxxx ready for work"
   - At scheduled time: notification checks will execute automatically

4. To reschedule the next cycle after execution:
   $ uv run trustpoint/manage.py execute_all_notifications --interval-hours 1

CONFIGURATION POINTS
====================

1. Global Enable/Disable:
   - Management > Settings > Notification Configuration
   - Toggle the "Enabled" checkbox
   - When disabled, no new checks are scheduled

2. Expiry Warning Thresholds:
   - cert_expiry_warning_days: Default 30 days
   - issuing_ca_expiry_warning_days: Default 30 days
   - Configured in the same Notification Configuration section

3. Cycle Interval:
   - Configure the interval in your scheduling mechanism (cron, Celery, etc.)
   - Default: 1 hour (can be overridden with --interval-hours flag)

COMPARISON WITH CRL GENERATION
===============================

CRL Generation Pattern:           Notification Scheduling Pattern:
├─ CaModel.schedule_next_...()   ├─ NotificationConfig.schedule_...()
├─ pki/tasks.py                  ├─ management/tasks.py
├─ generate_crl_for_ca()         ├─ execute_all_notifications()
├─ Django-Q2 schedule()          ├─ Django-Q2 schedule()
└─ process_tasks.py command      └─ execute_all_notifications.py command

Key Difference: CRL scheduling is per-CA, notification scheduling is global

USAGE EXAMPLES
==============

1. Start Q Cluster (first terminal):
   uv run trustpoint/manage.py qcluster

2. Initialize notification scheduling (second terminal):
   uv run trustpoint/manage.py init_notifications --interval-hours 1

3. Schedule with custom interval (4 hours between checks):
   uv run trustpoint/manage.py execute_all_notifications --interval-hours 4

4. Disable notifications temporarily:
   - Go to Management > Settings > Notification Configuration
   - Toggle "Enabled" off
   - No new checks will be scheduled
   - Existing scheduled tasks won't execute (checked at runtime)

5. Manual execution of all checks (without scheduling):
   uv run trustpoint/manage.py run_all_notifications

6. Set up automatic rescheduling with cron (every hour):
   0 * * * * cd /path/to/trustpoint && uv run trustpoint/manage.py execute_all_notifications

LOGGING
=======

Logs are available via:
- Logger name: 'management.tasks' or root logger
- Log level: INFO for main events, DEBUG for command execution
- Events logged:
  - Scheduling of next check
  - Start of notification execution
  - Completion of individual commands
  - Failures with full exception details

DJANGO-Q2 CONFIGURATION
=======================

The Q_CLUSTER settings (trustpoint/settings.py) should be configured:
Q_CLUSTER = {
    'name': 'trustpoint',
    'workers': 2,
    'recycle': 500,
    'timeout': 120,
    'retry': 360,
    'queue_limit': 50,
    'bulk': 10,
    'orm': 'default',
}

Task name format: 'management.tasks.execute_all_notifications'
Task path in schedule: 'management.tasks.execute_all_notifications'
Schedule type: 'O' (One-off/Single execution at specific time)
"""
