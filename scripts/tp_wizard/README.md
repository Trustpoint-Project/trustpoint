# tp_wizard

`tp_wizard.sh` is the developer-facing setup helper for the local trustpoint Docker stack.

It can run the interactive setup wizard or manage selected services: trustpoint, PostgreSQL, Mailpit, SFTPGo, and the optional workflows2 worker.

## Usage

Run from the repository root:

```bash
./tp_wizard.sh
./tp_wizard.sh up [demo|trustpoint|db|mail|sftp|worker] [--nowait]
./tp_wizard.sh down [demo|trustpoint|db|mail|sftp|worker]
./tp_wizard.sh logs [trustpoint|db|mail|sftp|worker]
./tp_wizard.sh status
./tp_wizard.sh nuke
```

## Design

The root `tp_wizard.sh` is only the public entrypoint. The implementation lives in `scripts/tp_wizard/`.

```text
defaults.sh      constants and default values
state.sh         mutable wizard/runtime state
cli.sh           argument parsing and dispatch
wizard.sh        interactive wizard flow
runtime.sh       shared start/wait/provision/summary orchestration
summary.sh       plan, status, and final summary output
lib/             generic helpers
services/        service-specific prompt/start/wait/provision logic
commands/        command handlers
```

Dependency direction:

```text
cli -> commands -> runtime -> services -> lib
wizard -> runtime -> services -> lib
```

Rules:

- `lib/` must not call service or command functions.
- `services/` may use `lib/`, but should not parse CLI arguments.
- `commands/` should stay thin and delegate shared work to `runtime.sh`.
- `runtime.sh` owns orchestration used by both wizard and CLI mode.
- The root `tp_wizard.sh` should remain small and stable.
