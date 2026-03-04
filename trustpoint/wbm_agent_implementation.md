# WBM Onboarding — Agent Implementation

> **Scope:** The standalone `trustpoint-agent` package deployed inside the production cell.
> See `wbm_onboarding_concept.md` for the overall architecture and `wbm_trustpoint_implementation.md` for the Trustpoint server side.

---

## Agent Role: Poll, Generate Key, Execute

**The agent has no scheduling logic.** It polls Trustpoint at a regular interval, and for each job returned it **generates a fresh key pair locally**, submits a CSR to Trustpoint, receives the signed certificate, and executes the Playwright workflow. The private key never leaves the agent.

The poll interval is configured in Trustpoint (`TrustpointAgent.poll_interval_seconds`) and returned in every check-in response. The agent adopts the server value immediately — no redeployment needed to change the interval.

```
Agent                                  Trustpoint
  |                                        |
  |  [every poll_interval_seconds]         |
  |── GET /api/agents/wbm/check-in/ ──────▶|  "Any work for me?"
  |◀── 200 { poll_interval_seconds,        |  Trustpoint decides what's due
  |          jobs: [{ job_id, base_url,    |  (expiry window / operator trigger)
  |                  key_spec, subject,    |  No cert or key in this response
  |                  workflow }] }         |
  |                                        |
  |  [Agent generates key pair + CSR]      |  Private key stays on agent
  |                                        |
  |── POST /api/agents/wbm/submit-csr/ ───▶|  { job_id, csr_pem }
  |◀── 200 { cert_pem, ca_bundle_pem } ────|  Trustpoint signs, returns cert only
  |                                        |
  |  [Playwright executes workflow]        |
  |                                        |
  |── POST /api/agents/wbm/push-result/ ──▶|  "job_id X: Succeeded / Failed"
  |◀── 200 ────────────────────────────────|
```

---

## 1. Repository & Package Layout

The agent lives in a **separate repository** (`trustpoint-agent`), completely independent of the Trustpoint Django project. It has no Django dependency and no database.

```
trustpoint-agent/
├── pyproject.toml
├── uv.lock
├── Dockerfile                         ← two-stage build
├── docker-compose.yml                 ← ready-to-use for cell operators
├── .env.example                       ← documents all AGENT_* variables
└── trustpoint_agent/
    ├── __init__.py
    ├── __main__.py                    ← entry point: python -m trustpoint_agent
    ├── config.py                      ← AgentConfig via pydantic-settings
    ├── scheduler.py                   ← per-target push schedule loop
    ├── wbm/
    │   ├── __init__.py
    │   ├── push.py                    ← push-request / push-result calls
    │   ├── executor.py                ← Playwright step runner
    │   └── verification.py           ← TLS fingerprint check after push
    └── credentials.py                ← local encrypted credentials store
```

The `wbm/` sub-package is the first capability module. Future capabilities (e.g. `firmware/`) sit alongside it at the same level.

---

## 2. Dependencies

```toml
# pyproject.toml
[project]
name = "trustpoint-wbm-agent"
requires-python = ">=3.12"

dependencies = [
    "httpx>=0.27",              # REST API polling (async, mTLS support)
    "pydantic-settings>=2.0",   # config from env vars
    "cryptography>=42",         # local credential file encryption (Fernet)
    "trustpoint-core",          # certificate/PEM utilities (shared with Trustpoint)
]

[project.optional-dependencies]
playwright = [
    "playwright>=1.44",         # Chromium automation — only needed for WBM browser path
]

[project.scripts]
wbm-agent = "trustpoint_wbm_agent.__main__:main"
```

`playwright` is an optional extra so the base package stays small. The Dockerfile installs it explicitly.

---

## 3. Entry Point

```python
# trustpoint_agent/__main__.py
import asyncio
import logging
from trustpoint_agent.config import AgentConfig
from trustpoint_agent.scheduler import run

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)

def main() -> None:
    """Start the Trustpoint Agent scheduler loop."""
    config = AgentConfig()
    asyncio.run(run(config))

if __name__ == "__main__":
    main()
```

---

## 4. Configuration

All parameters are injected via environment variables (Docker env / `.env` file). No values are hardcoded in the image.

Agent-identity variables (`AGENT_TRUSTPOINT_URL`, `AGENT_ID`, etc.) use a generic `AGENT_` prefix because they are shared regardless of which capabilities the agent runs. WBM-specific tuning variables keep a `WBM_` prefix.

```python
# trustpoint_wbm_agent/config.py
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict

class AgentConfig(BaseSettings):
    """Runtime configuration for the Trustpoint Agent, sourced from environment variables.

    Generic agent-identity variables use the AGENT_ prefix.
    WBM-specific variables use the WBM_ prefix.
    """

    # --- Generic agent identity (shared across all future capability types) ---

    trustpoint_url: str
    """Base URL of the Trustpoint server, e.g. https://trustpoint.example.com"""

    agent_id: str
    """Unique identifier for this agent instance, registered in Trustpoint as TrustpointAgent.agent_id."""

    client_cert_path: Path
    """Path to the mTLS client certificate issued by Trustpoint."""

    client_key_path: Path
    """Path to the private key for the mTLS client certificate."""

    initial_poll_interval_seconds: int = 60
    """Poll interval used until the first successful check-in returns the server-configured value.
    After the first check-in the agent always uses the value from Trustpoint."""

    # --- WBM-specific ---

    wbm_credentials_file: Path = Path("/run/secrets/credentials.enc")
    """Path to the local Fernet-encrypted WBM device credentials file."""

    wbm_step_timeout_ms: int = 20_000
    """Maximum time in milliseconds Playwright waits for each workflow step."""

    wbm_overall_timeout_ms: int = 180_000
    """Hard timeout in milliseconds for the entire Playwright run."""

    wbm_retries: int = 2
    """Number of times to retry the full WBM workflow on transient failure."""

    model_config = SettingsConfigDict(env_prefix="AGENT_")
```

> **Note:** `wbm_*` fields gain the env prefix too, so the actual env vars are `AGENT_WBM_CREDENTIALS_FILE`, `AGENT_WBM_STEP_TIMEOUT_MS`, etc. This keeps all agent vars under a single `AGENT_` namespace in the container environment.
>
> `AGENT_INITIAL_POLL_INTERVAL_SECONDS` is only relevant for the very first cycle. After the first successful check-in the agent uses `poll_interval_seconds` from the Trustpoint response and ignores this env var.

---

## 5. Local Credentials Store

The credentials file is a Fernet-encrypted JSON blob. The encryption key is derived from a machine-specific secret (mounted as a Docker secret). Credentials are keyed by `base_url` so the agent resolves them at job execution time.

```python
# trustpoint_wbm_agent/credentials.py
import json
from pathlib import Path
from cryptography.fernet import Fernet

class CredentialsStore:
    """Local encrypted store for WBM device credentials, keyed by base_url."""

    def __init__(self, credentials_file: Path, key: bytes) -> None:
        """Initialise the store.

        :param credentials_file: Path to the Fernet-encrypted credentials file.
        :param key: 32-byte URL-safe base64-encoded Fernet key.
        """
        self._file = credentials_file
        self._fernet = Fernet(key)

    def get(self, base_url: str) -> tuple[str, str]:
        """Return (username, password) for the given base_url.

        :param base_url: WBM base URL as received in the job payload.
        :raises KeyError: If no credentials are stored for this base_url.
        """
        data = self._load()
        entry = data[base_url]
        return entry["username"], entry["password"]

    def set(self, base_url: str, username: str, password: str) -> None:
        """Store or update credentials for the given base_url."""
        data = self._load()
        data[base_url] = {"username": username, "password": password}
        self._save(data)

    def _load(self) -> dict[str, dict[str, str]]:
        """Decrypt and parse the credentials file."""
        if not self._file.exists():
            return {}
        raw = self._fernet.decrypt(self._file.read_bytes())
        return json.loads(raw)  # type: ignore[return-value]

    def _save(self, data: dict[str, dict[str, str]]) -> None:
        """Encrypt and write the credentials file."""
        self._file.write_bytes(self._fernet.encrypt(json.dumps(data).encode()))
```

The encryption key itself is injected as a separate Docker secret (`WBM_FERNET_KEY` env var) and never stored in the image.

---

## 6. Scheduler Loop & WBM Push Cycle

The scheduler calls `GET /api/agents/wbm/check-in/` on every cycle. Trustpoint returns **only the jobs that are currently due** — the agent never evaluates expiry dates or decides whether a push is needed. It just executes what comes back.

The poll interval comes from Trustpoint in every response (`poll_interval_seconds`). The agent stores it in memory and uses it for the next `asyncio.sleep`. Changing the interval in Trustpoint takes effect after the agent's next successful check-in.

```python
# trustpoint_agent/scheduler.py
import asyncio
import logging
from pathlib import Path
import httpx
from trustpoint_agent.config import AgentConfig
from trustpoint_agent.credentials import CredentialsStore
from trustpoint_agent.wbm.push import wbm_execute_job

logger = logging.getLogger(__name__)


async def _check_in(config: AgentConfig) -> dict:
    """Call the Trustpoint check-in endpoint and return the parsed response.

    :returns: Dict with 'poll_interval_seconds' and 'jobs' list.
    :raises httpx.HTTPError: On network or HTTP errors.
    """
    async with httpx.AsyncClient(
        cert=(str(config.client_cert_path), str(config.client_key_path)),
        base_url=config.trustpoint_url,
    ) as client:
        resp = await client.get("/api/agents/wbm/check-in/")
        resp.raise_for_status()
        return resp.json()


async def run(config: AgentConfig) -> None:
    """Main scheduler loop. Runs until cancelled.

    Uses config.initial_poll_interval_seconds for the first cycle, then adopts
    the poll_interval_seconds value returned by Trustpoint on each check-in.
    """
    fernet_key = Path("/run/secrets/fernet.key").read_bytes().strip()
    store = CredentialsStore(config.wbm_credentials_file, fernet_key)

    poll_interval = config.initial_poll_interval_seconds
    logger.info(
        "Agent %s starting — initial interval %ds", config.agent_id, poll_interval
    )

    while True:
        try:
            response = await _check_in(config)
            poll_interval = response.get("poll_interval_seconds", poll_interval)
            jobs: list[dict] = response.get("jobs", [])
        except Exception as exc:  # noqa: BLE001 — top-level boundary, all errors must be caught
            logger.exception("Check-in failed: %s", exc)
            await asyncio.sleep(poll_interval)
            continue

        logger.debug("Check-in: %d job(s) due, next poll in %ds", len(jobs), poll_interval)

        for job in jobs:
            try:
                await wbm_execute_job(config, store, job)
            except Exception as exc:  # noqa: BLE001 — top-level boundary, all errors must be caught
                logger.exception("Unhandled error for job %s: %s", job.get("job_id"), exc)

        await asyncio.sleep(poll_interval)
```

```python
# trustpoint_agent/wbm/push.py
import logging
import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from trustpoint_agent.config import AgentConfig
from trustpoint_agent.credentials import CredentialsStore
from trustpoint_agent.wbm.executor import WorkflowExecutor
from trustpoint_agent.wbm.verification import verify_tls_fingerprint

logger = logging.getLogger(__name__)

_KEY_GENERATORS = {
    "EC_P256": lambda: ec.generate_private_key(ec.SECP256R1()),
    "EC_P384": lambda: ec.generate_private_key(ec.SECP384R1()),
    "RSA_2048": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    "RSA_4096": lambda: rsa.generate_private_key(public_exponent=65537, key_size=4096),
}

_OID_MAP = {
    "CN": NameOID.COMMON_NAME,
    "O":  NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "C":  NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L":  NameOID.LOCALITY_NAME,
}


def _generate_key_and_csr(key_spec: str, subject: dict[str, str]) -> tuple[bytes, str]:
    """Generate a key pair and a PEM-encoded CSR.

    :param key_spec: Algorithm identifier, e.g. 'EC_P256' or 'RSA_2048'.
    :param subject: Dict of X.509 name attributes, e.g. {'CN': 'device.example.com'}.
    :returns: Tuple of (key_pem_bytes, csr_pem_str). The key bytes are kept in memory
              and used for the Playwright workflow; they are never transmitted to Trustpoint.
    :raises ValueError: If key_spec is unknown.
    """
    generator = _KEY_GENERATORS.get(key_spec)
    if generator is None:
        raise ValueError(f"Unknown key_spec: {key_spec!r}. Supported: {list(_KEY_GENERATORS)}")

    private_key = generator()
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    name_attrs = [
        x509.NameAttribute(_OID_MAP[k], v)
        for k, v in subject.items()
        if k in _OID_MAP
    ]
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(name_attrs))
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, csr_pem


async def wbm_execute_job(
    config: AgentConfig,
    store: CredentialsStore,
    job: dict,
) -> None:
    """Execute a single WBM push job received from a Trustpoint check-in response.

    Flow:
    1. Generate a fresh key pair and CSR locally.
    2. Submit the CSR to Trustpoint; receive cert_pem + ca_bundle_pem.
    3. Resolve device credentials from the local store.
    4. Execute the Playwright workflow (cert + key used only in memory).
    5. Report the outcome to Trustpoint.

    The private key is generated fresh per job and held only in process memory.
    It is never written to disk and never transmitted to Trustpoint.

    :param config: Agent runtime configuration.
    :param store: Local encrypted credentials store.
    :param job: Job descriptor as received from the check-in endpoint.
                Contains: job_id, base_url, key_spec, subject, workflow.
    """
    job_id: int = job["job_id"]
    base_url: str = job["base_url"]
    tls_args: dict = dict(
        cert=(str(config.client_cert_path), str(config.client_key_path)),
        base_url=config.trustpoint_url,
    )

    # Step 1: generate key pair + CSR locally
    try:
        key_pem, csr_pem = _generate_key_and_csr(job["key_spec"], job["subject"])
    except ValueError as exc:
        await _report(config, job_id, "failed", str(exc))
        return

    # Step 2: submit CSR to Trustpoint, receive signed certificate
    async with httpx.AsyncClient(**tls_args) as client:
        resp = await client.post(
            "/api/agents/wbm/submit-csr/",
            json={"job_id": job_id, "csr_pem": csr_pem},
        )
        resp.raise_for_status()
        signed = resp.json()

    cert_pem: str = signed["cert_pem"]
    ca_bundle_pem: str = signed["ca_bundle_pem"]

    # Step 3: resolve device credentials
    try:
        username, password = store.get(base_url)
    except KeyError:
        await _report(config, job_id, "failed", f"No credentials stored for {base_url}")
        return

    # Step 4: execute the Playwright workflow
    executor = WorkflowExecutor(
        workflow=job["workflow"],
        variables={
            "base_url":      base_url,
            "username":      username,
            "password":      password,
            "cert_pem":      cert_pem,
            "key_pem":       key_pem.decode(),   # in-memory only, never persisted
            "ca_bundle_pem": ca_bundle_pem,
        },
        step_timeout_ms=config.wbm_step_timeout_ms,
        overall_timeout_ms=config.wbm_overall_timeout_ms,
    )

    for attempt in range(config.wbm_retries + 1):
        try:
            await executor.run()
            if not verify_tls_fingerprint(base_url, cert_pem):
                raise RuntimeError("TLS fingerprint after push does not match issued certificate.")
            await _report(config, job_id, "succeeded", "")
            return
        except Exception as exc:
            logger.warning("Job %d attempt %d failed: %s", job_id, attempt + 1, exc)
            if attempt == config.wbm_retries:
                await _report(config, job_id, "failed", str(exc))


async def _report(config: AgentConfig, job_id: int, status: str, detail: str) -> None:
    """Post the job outcome to Trustpoint."""
    async with httpx.AsyncClient(
        cert=(str(config.client_cert_path), str(config.client_key_path)),
        base_url=config.trustpoint_url,
    ) as client:
        await client.post(
            "/api/agents/wbm/push-result/",
            json={"job_id": job_id, "status": status, "detail": detail},
        )
```

---

## 7. Playwright Executor

```python
# trustpoint_agent/wbm/executor.py
import asyncio
import re
import logging
from typing import Any
from playwright.async_api import async_playwright, Page, TimeoutError as PlaywrightTimeout

logger = logging.getLogger(__name__)

_PLACEHOLDER = re.compile(r"\{\{(\w+)\}\}")

def _substitute(value: str, variables: dict[str, str]) -> str:
    """Replace all {{key}} placeholders with their values from the variables dict."""
    return _PLACEHOLDER.sub(lambda m: variables.get(m.group(1), m.group(0)), value)


class WorkflowExecutor:
    """Executes a sequence of Playwright-style workflow steps against a device WBM."""

    def __init__(
        self,
        workflow: list[dict[str, Any]],
        variables: dict[str, str],
        step_timeout_ms: int,
        overall_timeout_ms: int,
    ) -> None:
        """Initialise the executor.

        :param workflow: List of step dicts as received from Trustpoint.
        :param variables: Substitution variables including credentials and certificate material.
        :param step_timeout_ms: Per-step Playwright timeout in milliseconds.
        :param overall_timeout_ms: Hard overall timeout for the entire workflow run.
        """
        self._workflow = workflow
        self._variables = variables
        self._step_timeout_ms = step_timeout_ms
        self._overall_timeout_ms = overall_timeout_ms

    async def run(self) -> None:
        """Execute all workflow steps. Raises on any step failure."""
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page()
            try:
                await asyncio.wait_for(
                    self._run_steps(page),
                    timeout=self._overall_timeout_ms / 1000,
                )
            except asyncio.TimeoutError as exc:
                await self._screenshot(page, "timeout")
                raise RuntimeError("Overall workflow timeout exceeded") from exc
            except Exception:
                await self._screenshot(page, "error")
                raise
            finally:
                await browser.close()

    async def _run_steps(self, page: Page) -> None:
        """Execute each step in sequence."""
        for i, step in enumerate(self._workflow):
            step_type = step["type"]
            logger.debug("Step %d: %s", i, step_type)
            await self._execute_step(page, step)

    async def _execute_step(self, page: Page, step: dict[str, Any]) -> None:
        """Dispatch a single step to the appropriate Playwright call."""
        t = step["type"]
        timeout = step.get("timeout_ms", self._step_timeout_ms)

        if t == "goto":
            await page.goto(_substitute(step["url"], self._variables))
        elif t == "fill":
            await page.fill(step["selector"], _substitute(step["value"], self._variables), timeout=timeout)
        elif t == "click":
            await page.click(step["selector"], timeout=timeout)
        elif t == "uploadFile":
            content = _substitute(step["content"], self._variables)
            # Write to a temp file; Playwright's set_input_files requires a path.
            import tempfile, os
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pem", mode="w") as f:
                f.write(content)
                tmp_path = f.name
            try:
                await page.set_input_files(step["selector"], tmp_path, timeout=timeout)
            finally:
                os.unlink(tmp_path)
        elif t == "waitFor":
            await page.wait_for_selector(step["selector"], timeout=timeout)
        elif t == "expect":
            locator = page.locator(step["selector"])
            await locator.wait_for(timeout=timeout)
            text = await locator.inner_text()
            expected = _substitute(step.get("text", ""), self._variables)
            if expected and expected not in text:
                raise AssertionError(f"Expected '{expected}' in '{text}'")
        elif t == "screenshot":
            await self._screenshot(page, step.get("label", "manual"))
        elif t == "reboot":
            await page.click(step["selector"], timeout=timeout)
            await asyncio.sleep(step.get("wait_seconds", 60))
        else:
            raise ValueError(f"Unknown step type: {t}")

    async def _screenshot(self, page: Page, label: str) -> None:
        """Capture a debug screenshot. Logged at WARNING level; stored locally."""
        try:
            path = f"/tmp/wbm-agent-{label}.png"
            await page.screenshot(path=path)
            logger.warning("Screenshot saved: %s", path)
        except Exception as exc:
            logger.warning("Could not capture screenshot: %s", exc)
```

---

## 8. Post-Push Verification

After the workflow completes, the agent verifies the push succeeded by connecting to the device over HTTPS and comparing the TLS leaf certificate fingerprint against the newly issued certificate.

```python
# trustpoint_wbm_agent/verification.py
import ssl
import socket
import hashlib
from urllib.parse import urlparse

def verify_tls_fingerprint(base_url: str, expected_cert_pem: str) -> bool:
    """Check that the device at base_url is now serving the expected certificate.

    :param base_url: Device WBM URL, e.g. https://192.168.1.10.
    :param expected_cert_pem: PEM-encoded certificate that was just pushed.
    :returns: True if the fingerprints match, False otherwise.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    parsed = urlparse(base_url)
    host = parsed.hostname or ""
    port = parsed.port or 443

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)

    live_fp = hashlib.sha256(der).hexdigest().upper()

    expected_cert = x509.load_pem_x509_certificate(expected_cert_pem.encode())
    expected_fp = expected_cert.fingerprint(
        __import__("cryptography.hazmat.primitives.hashes", fromlist=["SHA256"]).SHA256()
    ).hex().upper()

    return live_fp == expected_fp
```

Called from `agent.py` after a successful executor run, before reporting `succeeded` to Trustpoint.

---

## 9. Dockerfile

```dockerfile
# Stage 1: install Python deps (cached unless pyproject.toml / uv.lock change)
FROM python:3.12-slim AS deps
COPY --from=ghcr.io/astral-sh/uv:latest /uv /bin/
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Stage 2: Playwright + Chromium (cached separately — ~300 MB layer)
FROM deps AS agent
RUN uv pip install "trustpoint-wbm-agent[playwright]" \
 && playwright install --with-deps chromium

COPY . .

# Run as non-root
RUN useradd -r -u 1001 wbmagent
USER wbmagent

CMD ["python", "-m", "trustpoint_wbm_agent"]
```

---

## 10. `docker-compose.yml`

```yaml
services:
  wbm-agent:
    image: trustpointproject/trustpoint-agent:latest
    restart: unless-stopped
    environment:
      AGENT_TRUSTPOINT_URL: "https://trustpoint.example.com"
      AGENT_AGENT_ID: "cell-a-agent-1"
      AGENT_CLIENT_CERT_PATH: "/run/secrets/agent.crt"
      AGENT_CLIENT_KEY_PATH:  "/run/secrets/agent.key"
      AGENT_INITIAL_POLL_INTERVAL_SECONDS: "60"   # used until first check-in; then server value applies
      AGENT_WBM_CREDENTIALS_FILE: "/run/secrets/credentials.enc"
      AGENT_WBM_RETRIES: "2"
    secrets:
      - agent.crt
      - agent.key
      - credentials.enc
      - fernet.key

secrets:
  agent.crt:
    file: ./secrets/agent.crt       # mTLS cert issued by Trustpoint
  agent.key:
    file: ./secrets/agent.key       # corresponding private key
  credentials.enc:
    file: ./secrets/credentials.enc # Fernet-encrypted device credentials
  fernet.key:
    file: ./secrets/fernet.key      # encryption key for credentials.enc
```

---

## 11. Agent Statelessness

The agent requires **no database** and has **no scheduling logic**. All decisions and execution material come from Trustpoint:

| Data | Source |
|---|---|
| Which jobs are due | `GET /api/agents/wbm/check-in/` — Trustpoint decides; agent only executes |
| Poll interval | `poll_interval_seconds` field in every check-in response; server-configurable |
| `key_spec`, `subject` | Included in the check-in job descriptor — used to generate the CSR |
| Private key | **Generated fresh on the agent per job; held in process memory only; never persisted or transmitted** |
| `cert_pem`, `ca_bundle_pem` | Returned by `POST /api/agents/wbm/submit-csr/` after CSR signing |
| `base_url` per job | Included in the check-in job descriptor |
| Workflow steps | Included in the check-in job descriptor |
| `username`, `password` | Local encrypted credentials file, keyed by `base_url` |
| Agent identity | mTLS cert/key mounted as Docker secrets |

The only persistent state on the agent host is the encrypted credentials file. Job history, scheduling logic, expiry thresholds, and target configuration all live exclusively in Trustpoint.

**Future extension — offline job cache:** If Trustpoint becomes temporarily unreachable, the agent cannot receive new jobs. A future version could cache the check-in job descriptors locally (SQLite) so CSR generation can be deferred and retried during a Trustpoint outage. This is deferred to avoid complexity in the initial implementation.

---

## 12. Open Items (Agent side)

- **CLI for credentials management** — a `wbm-agent credentials set/get/delete` command so cell operators can manage the credentials file without editing it manually
- **Fernet key rotation** — procedure for rotating the credentials file encryption key without downtime
- **Screenshot upload** — optionally POST failure screenshots to `PATCH /api/wbm/jobs/<id>/result/` as a multipart attachment so operators can see them in the Trustpoint UI
- **Per-step logging** — structured JSON log output per step for easier debugging in log aggregators (Loki, ELK)
