# v1.0.0 reference backup

This immutable synthetic demo fixture is used by the `restore-v1-reference` job
in `.github/workflows/backup-restore.yml`. The source commit and PostgreSQL
version are recorded in the adjacent text files; `demo.env` records its setup.

The dump and manifest belong together. `test-secrets.tar.gz` contains the original
Django signing key and software KEK required to restore this fixture. These are
public test keys: never use them or the fixture credentials in a real deployment.
Do not regenerate the backup or keys using newer application code.

The job restores into an empty PostgreSQL database, starts the current application
in operational mode (which applies migrations), and checks HTTPS/TLS, completed
migrations, admin authentication, demo data relationships, and a signature made
with a restored CA key. Auto-setup and demo-data injection stay disabled so they
cannot mask missing restored state.

Run the **Tests / Backup & Restore** workflow manually, or invoke it using
`workflow_call`. Coverage is limited to this software-backend demo installation.
