# Trustpoint Wizard

`tp_wizard.sh` is the public entrypoint. The implementation is split by responsibility:

- `defaults.sh`, `state.sh`: configuration and mutable run state
- `wizard.sh`: interactive questions
- `runtime.sh`: lifecycle and ordering
- `services/`: one module per container/service
- `commands/`: CLI dispatch and destructive operations
- `lib/`: small shell helpers

The repository `.env` is read as input. Wizard-generated values are written to `.env.tp_wizard`.

Examples:

```bash
./tp_wizard.sh
./tp_wizard.sh demo full --skip-setup
./tp_wizard.sh up trustpoint db
./tp_wizard.sh up worker
./tp_wizard.sh status
```

Demo presets do not start a workflows2 worker. Add it explicitly with
`./tp_wizard.sh up worker` when needed.
