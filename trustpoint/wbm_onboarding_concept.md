# WBM Onboarding — Feature Concept

## Problem & Motivation

Many brownfield OT devices only allow certificate changes through a Web-Based Management (WBM) interface—no EST, CMP, ACME, or any programmatic API. This makes certificate renewals and trust-store updates slow, manual, and error-prone, creating real outage risk when certificates expire.

Trustpoint solves this by adding WBM certificate automation: Trustpoint issues and holds the certificates as usual, then uses Playwright browser automation to operate the device's web UI like a human operator would—log in, navigate to the certificate page, upload a new certificate/key pair (or CA bundle), click apply, optionally trigger a device reboot/service restart, and verify success (UI confirmation plus HTTPS probe/fingerprint check).

---

## Architecture Overview

The feature is implemented as a new Django app `wbm` with the following responsibilities:

- **WbmOnboardingConfig** — per-device connection and authentication settings for the WBM interface
- **WbmWorkflowDefinition** — reusable, shareable Playwright-style JSON automation scripts, one per device family/firmware variant
- **WbmCertificateTarget** — links a specific `WbmOnboardingConfig` to a `WbmWorkflowDefinition` and a `CertificateProfileModel`, describing _what_ certificate to push and _how_

The `DeviceModel` is extended with a nullable FK to `WbmOnboardingConfig`, following the same pattern as the existing `onboarding_config` and `no_onboarding_config` FKs.

Certificate push runs are triggered either manually (via the UI) or automatically when a certificate issued to the device is about to expire (hooked into the existing Django-Q2 scheduler).

---

## Data Model

### `wbm.WbmOnboardingConfig` — per-device WBM connection config

Holds the network address, credentials, and HTTP-level settings needed to reach the device's WBM.

```python
class WbmOnboardingConfig(models.Model):
    """Connection and authentication settings for a device's Web-Based Management interface."""

    base_url = models.URLField(
        verbose_name=_("Base URL"),
        help_text=_("Base URL of the device WBM, e.g. https://192.168.1.10"),
    )
    username = models.CharField(verbose_name=_("Username"), max_length=200)
    password = EncryptedCharField(verbose_name=_("Password"), max_length=200)

    # TLS / network settings
    ignore_tls_errors = models.BooleanField(
        verbose_name=_("Ignore TLS Errors"),
        default=False,
        help_text=_("Skip TLS certificate verification for the WBM connection (use only in test environments)."),
    )
    extra_http_headers = models.JSONField(
        verbose_name=_("Extra HTTP Headers"),
        default=dict,
        blank=True,
        help_text=_("Additional HTTP headers to include in every request, as a JSON object."),
    )

    # Timeout / retry settings
    step_timeout_ms = models.PositiveIntegerField(
        verbose_name=_("Step Timeout (ms)"),
        default=20_000,
        help_text=_("Maximum time in milliseconds Playwright waits for each workflow step."),
    )
    overall_timeout_ms = models.PositiveIntegerField(
        verbose_name=_("Overall Timeout (ms)"),
        default=180_000,
        help_text=_("Hard timeout in milliseconds for the entire automation run."),
    )
    retries = models.PositiveIntegerField(
        verbose_name=_("Retries"),
        default=2,
        help_text=_("Number of times to retry the full workflow on transient failure."),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmOnboardingConfig({self.base_url})"
```

---

### `devices.DeviceModel` — add WBM config FK

`WbmOnboardingConfig` is added as a nullable FK on `DeviceModel`, consistent with the existing `onboarding_config` / `no_onboarding_config` FK pattern. `SET_NULL` ensures that deleting the config does not cascade-delete the device.

```python
# devices/models.py  (addition to existing DeviceModel fields)

wbm_onboarding_config = models.ForeignKey(
    "wbm.WbmOnboardingConfig",
    verbose_name=_("WBM Onboarding Config"),
    null=True,
    blank=True,
    on_delete=models.SET_NULL,
    related_name="devices",
)
```

> **Note:** `ForeignKey` (not `OneToOneField`) is used here so that the same `WbmOnboardingConfig` can be shared across devices of the same model with identical WBM credentials (e.g., a fleet of identical PLCs). If strict per-device isolation is required, this can be revisited.

---

### `wbm.WbmWorkflowDefinition` — reusable automation script

Stores the Playwright-style JSON automation profile. A single workflow definition can be reused by many devices of the same family/firmware. Workflow definitions are versioned and can be imported/exported via the UI.

```python
class WbmWorkflowDefinition(models.Model):
    """A reusable Playwright-style automation script for a specific device family or firmware variant."""

    name = models.CharField(verbose_name=_("Name"), max_length=200)
    vendor = models.CharField(verbose_name=_("Vendor"), max_length=120, blank=True)
    device_family = models.CharField(verbose_name=_("Device Family"), max_length=120, blank=True)
    firmware_hint = models.CharField(
        verbose_name=_("Firmware Hint"),
        max_length=120,
        blank=True,
        help_text=_("Optional firmware version or build string to help operators pick the right profile."),
    )
    version = models.CharField(verbose_name=_("Version"), max_length=40, default="1.0")
    description = models.TextField(verbose_name=_("Description"), blank=True)

    profile = models.JSONField(
        verbose_name=_("Workflow Profile"),
        help_text=_("JSON array of Playwright-style automation steps. See workflow schema documentation."),
    )
    is_active = models.BooleanField(
        verbose_name=_("Active"),
        default=True,
        help_text=_("Inactive definitions are hidden from selection but preserved for audit purposes."),
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("name", "version")]

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmWorkflowDefinition({self.name} v{self.version})"
```

#### Workflow JSON schema (example)

The `profile` field contains a JSON array of step objects. Each step has a `type` and type-specific parameters. Reserved variable placeholders (`{{cert_pem}}`, `{{key_pem}}`, `{{ca_bundle_pem}}`) are substituted by Trustpoint at runtime before the automation runs.

```json
[
  { "type": "goto",       "url": "{{base_url}}/login" },
  { "type": "fill",       "selector": "#username", "value": "{{username}}" },
  { "type": "fill",       "selector": "#password", "value": "{{password}}" },
  { "type": "click",      "selector": "#login-btn" },
  { "type": "waitFor",    "selector": ".dashboard", "timeout_ms": 10000 },
  { "type": "goto",       "url": "{{base_url}}/settings/certificates" },
  { "type": "uploadFile", "selector": "#cert-upload",  "content": "{{cert_pem}}" },
  { "type": "uploadFile", "selector": "#key-upload",   "content": "{{key_pem}}" },
  { "type": "uploadFile", "selector": "#ca-upload",    "content": "{{ca_bundle_pem}}" },
  { "type": "click",      "selector": "#apply-btn" },
  { "type": "expect",     "selector": ".success-banner", "text": "Certificate updated" },
  { "type": "waitFor",    "selector": ".reboot-complete", "timeout_ms": 60000 }
]
```

Supported step types: `goto`, `click`, `fill`, `uploadFile`, `waitFor`, `expect`, `screenshot` (debug capture), `reboot` (click + reconnect-wait).

---

### `wbm.WbmCertificateTarget` — what to push and how

Links a `WbmOnboardingConfig` to a `WbmWorkflowDefinition` and a `CertificateProfileModel`. One target = one certificate slot on the device. A device with multiple certificate slots (e.g., TLS server cert + client cert) has one `WbmCertificateTarget` per slot.

```python
class WbmCertificateTarget(models.Model):
    """Describes a single certificate slot on a device WBM and the workflow used to update it."""

    class SlotPurpose(models.TextChoices):
        """Semantic purpose of the certificate slot."""

        TLS_SERVER = "tls_server", _("TLS Server Certificate")
        TLS_CLIENT = "tls_client", _("TLS Client Certificate")
        CA_BUNDLE  = "ca_bundle",  _("CA / Trust-Store Bundle")
        OTHER      = "other",      _("Other")

    config = models.ForeignKey(
        "wbm.WbmOnboardingConfig",
        verbose_name=_("WBM Config"),
        on_delete=models.CASCADE,
        related_name="targets",
    )
    certificate_profile = models.ForeignKey(
        "pki.CertificateProfileModel",
        verbose_name=_("Certificate Profile"),
        on_delete=models.PROTECT,
        related_name="wbm_targets",
    )
    workflow = models.ForeignKey(
        "wbm.WbmWorkflowDefinition",
        verbose_name=_("Workflow Definition"),
        on_delete=models.PROTECT,
        related_name="targets",
    )

    purpose = models.CharField(
        verbose_name=_("Slot Purpose"),
        max_length=20,
        choices=SlotPurpose,
        default=SlotPurpose.TLS_SERVER,
    )
    slot = models.CharField(
        verbose_name=_("Slot Identifier"),
        max_length=80,
        blank=True,
        default="",
        help_text=_("Optional device-specific slot name (e.g. 'slot0'), for devices with multiple cert slots."),
    )
    enabled = models.BooleanField(verbose_name=_("Enabled"), default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = [("config", "purpose", "slot")]

    def __str__(self) -> str:
        """Return a human-readable representation."""
        return f"WbmCertificateTarget({self.config} {self.purpose}/{self.slot} → {self.certificate_profile})"
```


## Execution Flow

1. **Trigger** — A Django-Q2 task (`wbm.tasks.push_certificate`) is enqueued either manually (UI button) or by the certificate-expiry scheduler when an issued credential is within the configured renewal window.
2. **Certificate issuance** — The task fetches (or issues) the certificate via the existing `CertificateIssueProcessor`, using the `certificate_profile` from the `WbmCertificateTarget`.
3. **Variable substitution** — `cert_pem`, `key_pem`, `ca_bundle_pem`, `base_url`, `username`, `password` placeholders in the workflow JSON are substituted with real values. Credentials are loaded from the encrypted fields and are never written to disk or logs.
4. **Playwright execution** — A headless Chromium browser (via the `playwright` Python package, installed as an optional dependency) executes the steps sequentially. Per-step and overall timeouts are enforced. On failure the current page is screenshotted.
5. **Verification** — After the final workflow step, Trustpoint opens an HTTPS connection to `base_url` and compares the TLS leaf certificate fingerprint against the newly issued certificate. A mismatch counts as failure.
6. **Logging** — The outcome, duration, and any error details are logged via Trustpoint's standard logging infrastructure.
7. **Retry**— If `retries > 0` and the run failed with a transient error (timeout, network), the task re-enqueues itself up to the configured retry count.

---

## Open Questions / Future Work

- **Credential isolation**: Should `WbmOnboardingConfig` be `OneToOneField` (strict per-device) or `ForeignKey` (shared across a fleet)? The current proposal uses `ForeignKey` for fleet flexibility, but this means a compromised config exposes multiple devices.
- **Playwright dependency**: The `playwright` Python package itself is small (~5 MB), but bundled browser binaries add ~300 MB. To keep the image lean, do **not** ship browser binaries inside the wheel; instead run `playwright install --with-deps chromium` as a dedicated, cacheable Docker layer that is only included when the `[wbm]` optional extra is enabled. The Python package should be an opt-in `[wbm]` extra in `pyproject.toml` and gated behind a feature flag (see existing `features` app). Pure-HTTP alternatives (`httpx`, `mechanize`) are too lightweight to handle JS-rendered WBM UIs and are not recommended; `pyppeteer` is largely unmaintained since 2022.
- **Workflow validation**: The `profile` JSON field should be validated against a JSON Schema on save (either in `Model.clean()` or a custom `JSONSchemaValidator`).
- **UI**: A workflow definition editor/importer, a per-device "push now" button, and an execution log list view are needed in the `wbm` app's views and templates.
- **Secret rotation**: When a device password changes, only the `WbmOnboardingConfig` needs updating — the workflow definition is reusable across that change.
