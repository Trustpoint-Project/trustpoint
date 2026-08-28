# Trustpoint Wizard

`tp_wizard.sh` is the public entrypoint. The implementation is split by responsibility:

- `defaults.sh`, `state.sh`: configuration and mutable run state
- `wizard.sh`: interactive questions
- `runtime.sh`: lifecycle and ordering
- `services/`: one module per container/service
- `commands/`: CLI dispatch and destructive operations
- `lib/`: small shell helpers

The repository `.env` is read as input. Wizard-generated values are written to `.env.tp_wizard`.
The interactive command prompts for service configuration and keeps Trustpoint's
in-app setup wizard enabled by default. Automatic setup is opt-in with
`--skip-wizard` or the corresponding interactive question. The older
`--skip-setup` spelling remains an alias.

Examples:

```bash
./tp_wizard.sh
./tp_wizard.sh demo full --skip-wizard
./tp_wizard.sh demo --soft-hsm
./tp_wizard.sh up trustpoint db --skip-wizard
./tp_wizard.sh up trustpoint db --soft-hsm
./tp_wizard.sh up worker
./tp_wizard.sh status
```

Demo presets do not start a workflows2 worker. Add it explicitly with
`./tp_wizard.sh up worker` when needed.

`--soft-hsm` starts the local demo SoftHSM and exposes its initialized token to
Trustpoint's in-app setup wizard. `--usb-hsm` instead exposes the host USB bus;
the two options are mutually exclusive.
