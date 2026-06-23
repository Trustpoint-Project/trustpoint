# tp_wizard

`tp_wizard.sh` is the developer-facing setup helper for the local trustpoint Docker stack.

It can run the interactive setup wizard or manage selected runtime services: trustpoint, PostgreSQL, Mailpit, SFTPGo, the optional workflows2 worker, Prometheus, and Grafana.

## Commands

Run from the repository root:

```bash
./tp_wizard.sh
./tp_wizard.sh demo [light|full] [--skip-setup|--no-skip-setup] [--nowait]
./tp_wizard.sh up [trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring] [--skip-setup|--no-skip-setup] [--nowait]
./tp_wizard.sh down [trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring]
./tp_wizard.sh logs [trustpoint|db|mail|sftp|worker|prometheus|grafana]
./tp_wizard.sh status
./tp_wizard.sh nuke
```

Demo presets:

```text
./tp_wizard.sh demo light  = trustpoint + PostgreSQL
./tp_wizard.sh demo        = trustpoint + PostgreSQL + Mailpit + SFTPGo + workflows2 worker
./tp_wizard.sh demo full   = demo + Prometheus + Grafana
```


`up` is intentionally only for explicit service targets. Demo presets are intentionally only available through `demo`.

## Environment files

The wizard reads `.env` as project input, but does not modify it by default.
Generated runtime values are written to `.env.tp_wizard`.

Containers started by the wizard receive env files in this order:

```text
.env -> .env.tp_wizard -> explicit docker run -e values
```

To intentionally let the wizard write into `.env` directly:

```bash
TP_WIZARD_WRITE_PROJECT_ENV=true ./tp_wizard.sh demo light --skip-setup
```

The setup-skip variable defaults to `false`. Enable it per run with:

```bash
./tp_wizard.sh demo full --skip-setup
./tp_wizard.sh up trustpoint db --skip-setup
```

If the application uses a different variable name:

```bash
TRUSTPOINT_SKIP_SETUP_ENV_KEY=YOUR_ENV_NAME ./tp_wizard.sh demo light --skip-setup
```

## Output style

`status`, the setup plan, and the final summary are intentionally compact:

- one service table
- important access URLs only
- env-file overlay information
- database connection target without passwords
- only essential credentials, masked


## Monitoring auto-provisioning

`demo full` starts Prometheus and Grafana with generated config under `.tp_wizard/`.
This avoids overwriting repository files such as `prometheus/prometheus.yml`.

Generated files:

```text
.tp_wizard/prometheus/prometheus.yml
.tp_wizard/grafana/provisioning/datasources/prometheus.yml
.tp_wizard/grafana/provisioning/dashboards/trustpoint.yml
.tp_wizard/grafana/dashboards/trustpoint-overview.json
```

Prometheus scrapes trustpoint with these defaults:

```text
TRUSTPOINT_METRICS_SCHEME=https
TRUSTPOINT_METRICS_TARGET=trustpoint.local:443
TRUSTPOINT_METRICS_PATH=/prometheus/metrics
```

Override them when needed:

```bash
TRUSTPOINT_METRICS_PATH=/your/metrics/path ./tp_wizard.sh demo full
```

Grafana is provisioned with a Prometheus datasource and a `Trustpoint Overview` dashboard.

## Design

The root `tp_wizard.sh` is only the stable entrypoint. Implementation lives in `scripts/tp_wizard/`:

```text
defaults.sh          constants and defaults; loads .env early
state.sh             mutable wizard/runtime state
cli.sh               argument parsing and dispatch
wizard.sh            interactive wizard flow
runtime.sh           shared start/wait/provision/summary orchestration
summary.sh           compact plan, status, and final output
lib/                 generic helpers
services/            service-specific logic
commands/            command handlers
```

Dependency direction:

```text
cli -> commands -> runtime -> services -> lib
wizard -> runtime -> services -> lib
```

Rules: `lib/` does not call services or commands; services do not parse CLI args; commands stay thin; `runtime.sh` owns shared orchestration.


## Demo/up split and setup skip

`demo` is the only command for presets:

```bash
./tp_wizard.sh demo light --skip-setup
./tp_wizard.sh demo --skip-setup
./tp_wizard.sh demo full --skip-setup
```

`up` is only for explicit services:

```bash
./tp_wizard.sh up trustpoint db --skip-setup
./tp_wizard.sh up prometheus grafana
```

`up demo full` is intentionally invalid.

The `--skip-setup` flag sets the configured trustpoint setup-skip environment variable to `true`.
By default the wizard writes:

```text
TP_SKIP_SETUP=true
```

If the application-side variable name changes, override it without editing the script:

```bash
TRUSTPOINT_SKIP_SETUP_ENV_KEY=REAL_ENV_NAME ./tp_wizard.sh demo full --skip-setup
```

To write more than one compatible variable name:

```bash
TRUSTPOINT_SKIP_SETUP_ENV_KEYS="TP_SKIP_SETUP REAL_ENV_NAME" ./tp_wizard.sh demo full --skip-setup
```
