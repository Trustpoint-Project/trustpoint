# tp_wizard

`tp_wizard.sh` is the developer-facing setup helper for the local trustpoint Docker stack.

It can run the interactive setup wizard or manage selected runtime services: trustpoint, PostgreSQL, Mailpit, SFTPGo, workflows2 worker, Prometheus, and Grafana.

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

```bash
./tp_wizard.sh up demo light    # trustpoint + PostgreSQL
./tp_wizard.sh up demo          # trustpoint + PostgreSQL + Mailpit + SFTPGo + workflows2 worker
./tp_wizard.sh up demo full     # demo + Prometheus + Grafana
```

## Design

The root `tp_wizard.sh` stays small and only bootstraps the implementation in `scripts/tp_wizard/`.

```text
defaults.sh          constants and default values
state.sh             mutable wizard/runtime state
cli.sh               argument parsing and dispatch
wizard.sh            interactive wizard flow
runtime.sh           shared start/wait/provision/summary orchestration
summary.sh           planned/live/final output
lib/                 generic helpers
services/            service-specific prompt/start/wait/provision logic
commands/            command handlers
```

Dependency direction:

```text
cli -> commands -> runtime -> services -> lib
wizard -> runtime -> services -> lib
```

Keep command handlers thin. Shared startup logic belongs in `runtime.sh`; service details belong in `services/`.
