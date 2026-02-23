# Setting Up Notification Checks with Django-Q2

This guide explains how to set up and manage periodic notification checks in Trustpoint using Django-Q2.

## Quick Start

### Prerequisites
- Trustpoint application running
- Database available (PostgreSQL or SQLite)
- Q Cluster service configured in Django settings

### Step 1: Start the Q Cluster Service

Open a terminal and run:

```bash
cd trustpoint
uv run trustpoint/manage.py qcluster
```

You should see output like:
```
Q Cluster [trustpoint] running.
Process-xxxx ready for work
Process-xxxx monitoring at xxxxx
```

**Keep this terminal running!** Q Cluster needs to be active to execute scheduled tasks.

### Step 2: Initialize Notification Scheduling

In another terminal, run:

```bash
cd trustpoint
uv run trustpoint/manage.py init_notifications --interval-minutes 5
```

You should see:
```
✓ Notification checking initialized successfully!
  Next check scheduled in 5 minute(s).
  Make sure the Q Cluster is running: uv run trustpoint/manage.py qcluster
```

**That's it!** The first notification check is now scheduled to run in 5 minutes.

## Understanding the System

### What Happens Automatically

1. **Scheduling**: You run `init_notifications` to schedule the first check
2. **Execution**: At the scheduled time, Q Cluster automatically runs the check
3. **Processing**: All 10 notification checks execute sequentially:
   - System health checks
   - Security vulnerability checks
   - Certificate expiration checks
   - Domain and device checks
   - Algorithm strength checks

### Configuration Points

**Global Notifications Toggle:**
- Go to **Management > Settings > Notification Configuration**
- Toggle **Enabled** on/off to control all notifications globally
- When disabled, no checks will execute even if scheduled

**Expiry Warning Thresholds:**
- **Certificate expiry warning days**: Default 30 days
- **Issuing CA expiry warning days**: Default 30 days

## Managing Notification Schedules

### Reschedule Next Cycle

After the first check completes, you can manually reschedule the next one:

```bash
uv run trustpoint/manage.py execute_all_notifications --interval-minutes 5
```

### Custom Interval

Check every 10 minutes instead of 5:

```bash
uv run trustpoint/manage.py execute_all_notifications --interval-minutes 10
```

### Automated Rescheduling with Cron

To automatically reschedule checks every 5 minutes, add this to crontab:

```bash
*/5 * * * * cd /path/to/trustpoint && uv run trustpoint/manage.py execute_all_notifications --interval-minutes 5
```

This ensures continuous notification checking without manual intervention.

## Usage Examples

### Start Q Cluster (first terminal):
```bash
uv run trustpoint/manage.py qcluster
```

### Initialize notification scheduling (second terminal):
```bash
uv run trustpoint/manage.py init_notifications --interval-minutes 5
```

### Schedule with custom interval (10 minutes between checks):
```bash
uv run trustpoint/manage.py execute_all_notifications --interval-minutes 10
```

### Disable notifications temporarily:
- Go to **Management > Settings > Notification Configuration**
- Toggle **Enabled** off
- No new checks will be scheduled
- Existing scheduled tasks won't execute (checked at runtime)

### Manual execution of all checks (without scheduling):
```bash
uv run trustpoint/manage.py run_all_notifications
```

### Set up automatic rescheduling with cron (every 5 minutes):
```bash
*/5 * * * * cd /path/to/trustpoint && uv run trustpoint/manage.py execute_all_notifications --interval-minutes 5
```

### "Q Cluster is not executing tasks"

**Solution**: Make sure Q Cluster is running in a separate terminal:
```bash
uv run trustpoint/manage.py qcluster
```

### "Tasks are scheduled but not executing"

**Possible causes**:
1. Q Cluster is not running
2. Notifications are disabled (check Management > Settings)
3. Database connection issue with Q Cluster

**Solution**: Check Q Cluster logs for errors and ensure database is accessible.

### "Notifications are disabled"

**Solution**: Enable notifications in Management > Settings > Notification Configuration

## Commands Reference

| Command | Purpose | Usage |
|---------|---------|-------|
| `init_notifications` | Initialize notification scheduling | `uv run trustpoint/manage.py init_notifications [--interval-minutes N]` |
| `execute_all_notifications` | Schedule the next check | `uv run trustpoint/manage.py execute_all_notifications [--interval-minutes N]` |
| `run_all_notifications` | Execute all checks immediately | `uv run trustpoint/manage.py run_all_notifications` |

## Architecture

The notification system uses Django-Q2 for background task execution:

```
User Action
    ↓
init_notifications command
    ↓
NotificationConfig.schedule_next_notification_check()
    ↓
Django-Q2 stores scheduled task
    ↓
Q Cluster worker picks up task at scheduled time
    ↓
management.tasks.execute_all_notifications()
    ↓
run_all_notifications command
    ↓
All 10 notification checks execute sequentially
    ↓
Results logged and notifications created
```

## Best Practices

1. **Always keep Q Cluster running** in the background for production
2. **Set up automatic rescheduling** with cron to maintain continuous checks
3. **Monitor Q Cluster logs** for errors and task execution
4. **Use Management > Settings** to control notification behavior globally
5. **Test with manual execution** first: `run_all_notifications`

## For Developers

See `NOTIFICATION_SCHEDULING.md` for detailed architecture documentation and implementation details.
