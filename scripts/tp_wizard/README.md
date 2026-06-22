# tp_wizard

`tp_wizard.sh` is the developer-facing setup helper for the local trustpoint Docker stack.

It can run the interactive setup wizard or manage selected runtime services: trustpoint, PostgreSQL, Mailpit, SFTPGo, the optional workflows2 worker, Prometheus, and Grafana.

## Commands

Run from the repository root:

```bash
./tp_wizard.sh
./tp_wizard.sh up [demo [light|full]|trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring] [--nowait]
./tp_wizard.sh down [demo [light|full]|trustpoint|db|mail|sftp|worker|prometheus|grafana|monitoring]
./tp_wizard.sh logs [trustpoint|db|mail|sftp|worker|prometheus|grafana]
./tp_wizard.sh status
./tp_wizard.sh nuke
```

Demo presets:

```text
demo light  = trustpoint + PostgreSQL
demo        = trustpoint + PostgreSQL + Mailpit + SFTPGo + workflows2 worker
demo full   = demo + Prometheus + Grafana
```

## Environment handling

The wizard reads and updates `.env` before starting trustpoint containers. The file is used for database settings, TLS host settings, host ports, and the trustpoint setup-skip flag.

Default setup-skip variable:

```text
TP_SKIP_SETUP=true
```

If the application uses a different variable name, run the wizard with:

```bash
TRUSTPOINT_SKIP_SETUP_ENV_KEY=YOUR_ENV_NAME ./tp_wizard.sh up demo light
```

## Design

The root `tp_wizard.sh` is only the stable entrypoint. Implementation lives in `scripts/tp_wizard/`:

```text
defaults.sh          constants and defaults; loads .env early
state.sh             mutable wizard/runtime state
cli.sh               argument parsing and dispatch
wizard.sh            interactive wizard flow
runtime.sh           shared start/wait/provision/summary orchestration
summary.sh           plan, status, and final output
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
## Environment files

The wizard reads the repository `.env` as input, but does not modify it by default.
Generated runtime values are written to `.env.tp_wizard`. Containers started by
the wizard receive `.env` first and `.env.tp_wizard` second, followed by explicit
`docker run -e` values for the active wizard selection.

To intentionally let the wizard update `.env` directly, run with:

```bash
TP_WIZARD_WRITE_PROJECT_ENV=true ./tp_wizard.sh up demo light
```

When the wizard writes to an existing env file, it creates a timestamped backup
next to that file before changing it.

