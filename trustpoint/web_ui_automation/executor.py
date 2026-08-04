# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Headless Playwright executor for declarative Web UI automation profiles."""

from __future__ import annotations

import concurrent.futures
import hashlib
import re
import socket
import ssl
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlsplit

if TYPE_CHECKING:
    from collections.abc import Callable

from django.core.exceptions import ValidationError
from django.utils import timezone
from playwright.sync_api import Browser, BrowserContext, Locator, Page, sync_playwright
from playwright.sync_api import Error as PlaywrightError

from web_ui_automation.models import (
    AuthenticationType,
    JobResult,
    JobStatus,
    StepStatus,
    VerificationStatus,
    WebUiAutomationJob,
    WebUiAutomationStepLog,
)
from web_ui_automation.schema import validate_profile_schema
from web_ui_automation.services import record_job_failure, record_job_success

DEFAULT_TIMEOUT_MS = 30_000


def _run_db[T](func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Run a database-touching callable in a plain worker thread.

    Playwright's sync API drives an asyncio event loop in the current thread, so
    Django's ORM refuses to run there (SynchronousOnlyOperation). Executing the
    callable in a fresh thread (which has no running event loop) sidesteps this.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(func, *args, **kwargs).result()


class StepExecutionError(RuntimeError):
    """An expected, sanitized failure while executing a profile step."""

    def __init__(self, step_id: str, category: str, message: str) -> None:
        """Initialize a step execution error."""
        self.step_id = step_id
        self.category = category
        super().__init__(message)


@dataclass(slots=True)
class ExecutionContext:
    """Runtime values available to declarative profile steps."""

    values: dict[str, str] = field(default_factory=dict)
    output_values: dict[str, str] = field(default_factory=dict)

    def resolve(self, value: Any) -> Any:
        """Resolve an exact `{{ variable }}` reference without evaluating templates."""
        if not isinstance(value, str):
            return value
        match = re.fullmatch(r'\{\{\s*([a-zA-Z0-9_]+)\s*\}\}', value)
        if match is None:
            return value
        variable = match.group(1)
        if variable in self.values:
            return self.values[variable]
        if variable in self.output_values:
            return self.output_values[variable]
        raise KeyError(variable)


@dataclass(slots=True)
class VerificationSummary:
    """Aggregate optional postcondition results."""

    configured: int = 0
    passed: int = 0
    failed: int = 0

    @property
    def status(self) -> str:
        """Return the corresponding persisted verification status."""
        if self.configured == 0:
            return VerificationStatus.NOT_CONFIGURED
        if self.failed == 0:
            return VerificationStatus.PASSED
        if self.passed:
            return VerificationStatus.PARTIAL
        return VerificationStatus.FAILED

    @property
    def result(self) -> str:
        """Return the corresponding job result."""
        if self.failed:
            return JobResult.PARTIALLY_SUCCESSFUL
        return JobResult.SUCCESSFUL


def execute_job(job_id: int) -> None:
    """Execute one queued Web UI automation job synchronously."""
    job = WebUiAutomationJob.objects.select_related(
        'assignment__automation_device__device',
        'assignment__workflow_definition',
        'assignment__issued_credential__credential__certificate',
        'candidate_certificate',
    ).get(pk=job_id)
    if job.status != JobStatus.QUEUED:
        msg = 'Only queued jobs may be executed.'
        raise ValidationError(msg)

    job.assignment.workflow_definition.validate_before_execution()
    validate_profile_schema(job.profile_snapshot)
    job.status = JobStatus.RUNNING
    job.started_at = timezone.now()
    job.save(update_fields=['status', 'started_at'])

    try:
        with tempfile.TemporaryDirectory(prefix=f'trustpoint-webui-{job.pk}-') as temporary_directory:
            context = _build_execution_context(job, Path(temporary_directory))
            verification = _execute_browser_profile(job, context)
    except StepExecutionError as exc:
        record_job_failure(
            job,
            failed_step_id=exc.step_id,
            failure_category=exc.category,
            error_message=str(exc),
        )
    except (OSError, PlaywrightError, ValidationError, ValueError, KeyError) as exc:
        record_job_failure(
            job,
            failed_step_id='',
            failure_category=type(exc).__name__,
            error_message=str(exc),
        )
    else:
        record_job_success(job, result=verification.result, verification_status=verification.status)


def _build_execution_context(job: WebUiAutomationJob, temporary_directory: Path) -> ExecutionContext:
    """Resolve secrets and write short-lived PEM artifacts for one job."""
    automation_device = job.assignment.automation_device
    values = {
        'device_username': automation_device.get_username(),
        'device_password': automation_device.get_password(),
        'private_key_password': automation_device.get_private_key_password(),
    }

    if job.operation in {'onboard', 'renew'}:
        if job.candidate_certificate is None:
            msg = 'A candidate certificate is required.'
            raise ValidationError(msg)
        if job.assignment.issued_credential is None:
            msg = 'The assignment has no issued credential.'
            raise ValidationError(msg)

        credential = job.assignment.issued_credential.credential
        if not credential.private_key:
            msg = 'Phase 1 requires an exportable PEM private key. Managed non-exportable keys are unsupported.'
            raise ValidationError(msg)

        certificate_path = temporary_directory / 'certificate.pem'
        private_key_path = temporary_directory / 'private-key.pem'
        certificate_path.write_text(job.candidate_certificate.cert_pem, encoding='ascii')
        private_key_path.write_text(credential.private_key, encoding='ascii')
        certificate_path.chmod(0o600)
        private_key_path.chmod(0o600)

        values.update(
            {
                'certificate_pem': str(certificate_path),
                'private_key_pem': str(private_key_path),
                'certificate_sha256_fingerprint': job.candidate_certificate.sha256_fingerprint,
            }
        )
    return ExecutionContext(values=values)


def _execute_browser_profile(job: WebUiAutomationJob, runtime: ExecutionContext) -> VerificationSummary:
    """Run profile steps and optional postconditions in a new headless browser context."""
    operation = job.profile_snapshot['operations'][job.operation]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            browser_context = _create_browser_context(browser, job)
            try:
                page = browser_context.new_page()
                page.set_default_timeout(DEFAULT_TIMEOUT_MS)
                for sequence, step in enumerate(operation['steps'], start=1):
                    _execute_and_log_step(job, page, step, runtime, sequence)
                return _execute_postconditions(job, page, operation.get('postconditions', []), runtime)
            finally:
                browser_context.close()
        finally:
            browser.close()


def _create_browser_context(browser: Browser, job: WebUiAutomationJob) -> BrowserContext:
    """Create a fresh browser context and configure HTTP Basic Authentication when selected."""
    automation_device = job.assignment.automation_device
    context_options: dict[str, Any] = {
        'accept_downloads': True,
        'ignore_https_errors': False,
        'locale': 'en-US',
    }
    if automation_device.authentication_type == AuthenticationType.HTTP_BASIC:
        context_options['http_credentials'] = {
            'username': _run_db(automation_device.get_username),
            'password': _run_db(automation_device.get_password),
        }
    return browser.new_context(**context_options)


def _execute_postconditions(
    job: WebUiAutomationJob,
    page: Page,
    postconditions: list[dict[str, Any]],
    runtime: ExecutionContext,
) -> VerificationSummary:
    """Execute optional verification steps without treating conflicts as browser-step failures."""
    summary = VerificationSummary(configured=len(postconditions))
    sequence_offset = len(job.profile_snapshot['operations'][job.operation]['steps'])
    for offset, step in enumerate(postconditions, start=1):
        try:
            _execute_and_log_step(job, page, step, runtime, sequence_offset + offset)
        except StepExecutionError:
            summary.failed += 1
        else:
            summary.passed += 1
    return summary


def _execute_and_log_step(
    job: WebUiAutomationJob,
    page: Page,
    step: dict[str, Any],
    runtime: ExecutionContext,
    sequence: int,
) -> None:
    """Execute a step and persist a sanitized step-level log."""
    step_log = _run_db(
        WebUiAutomationStepLog.objects.create,
        job=job,
        sequence=sequence,
        step_id=step['id'],
        action=step['action'],
    )
    try:
        _execute_step(job, page, step, runtime)
    except (PlaywrightError, OSError, ValueError, KeyError, ssl.SSLError) as exc:
        step_log.status = StepStatus.FAILED
        step_log.message = _sanitized_step_message(step, success=False)
        step_log.finished_at = timezone.now()
        _run_db(step_log.save, update_fields=['status', 'message', 'finished_at'])
        error_message = 'Sensitive step failed.' if step.get('sensitive') else str(exc)
        raise StepExecutionError(step['id'], type(exc).__name__, error_message) from exc
    else:
        step_log.status = StepStatus.SUCCESSFUL
        step_log.message = _sanitized_step_message(step, success=True)
        step_log.finished_at = timezone.now()
        _run_db(step_log.save, update_fields=['status', 'message', 'finished_at'])


def _execute_step(
    job: WebUiAutomationJob,
    page: Page,
    step: dict[str, Any],
    runtime: ExecutionContext,
) -> None:
    """Execute one allow-listed declarative profile step."""
    action = step['action']
    timeout = step.get('timeout_ms', DEFAULT_TIMEOUT_MS)

    if action == 'goto':
        target_url = _build_target_url(job.assignment.automation_device.base_url, job.profile_snapshot, step)
        page.goto(target_url, wait_until='domcontentloaded', timeout=timeout)
        _assert_same_origin(job.assignment.automation_device.base_url, page.url)
        return
    if action == 'reload':
        page.reload(wait_until='domcontentloaded', timeout=timeout)
        return
    if action == 'go_back':
        page.go_back(wait_until='domcontentloaded', timeout=timeout)
        return
    if action == 'verify_tls_certificate':
        expected = runtime.resolve(step.get('expected_fingerprint', '{{ certificate_sha256_fingerprint }}'))
        _verify_tls_fingerprint(job.assignment.automation_device.base_url, str(expected))
        return
    if action == 'compare_fingerprint':
        actual = _normalize_fingerprint(str(runtime.resolve(step['value'])))
        expected = _normalize_fingerprint(str(runtime.resolve(step['expected'])))
        if actual != expected:
            msg = 'The certificate fingerprints do not match.'
            raise ValueError(msg)
        return

    locator = _get_locator(page, step)
    if action == 'click':
        locator.click(timeout=timeout)
    elif action == 'click_if_visible':
        _click_first_visible(page, step, timeout)
    elif action in {'commit_configuration', 'restart_service', 'reboot_device'}:
        locator.click(timeout=timeout, no_wait_after=True)
    elif action == 'fill':
        locator.fill(str(runtime.resolve(step['value'])), timeout=timeout)
    elif action == 'select':
        locator.select_option(str(runtime.resolve(step['value'])), timeout=timeout)
    elif action == 'check':
        locator.check(timeout=timeout)
    elif action == 'uncheck':
        locator.uncheck(timeout=timeout)
    elif action == 'upload':
        locator.set_input_files(str(runtime.resolve(step['artifact'])), timeout=timeout)
    elif action == 'press':
        locator.press(step['key'], timeout=timeout)
    elif action == 'focus':
        locator.focus(timeout=timeout)
    elif action == 'hover':
        locator.hover(timeout=timeout)
    elif action == 'wait_for':
        locator.wait_for(state=step.get('state', 'visible'), timeout=timeout)
    elif action == 'wait_for_navigation':
        page.wait_for_load_state('domcontentloaded', timeout=timeout)
    elif action == 'wait_for_network_idle':
        page.wait_for_load_state('networkidle', timeout=timeout)
    elif action == 'assert_visible':
        if not locator.is_visible(timeout=timeout):
            msg_0 = 'Expected element is not visible.'
            raise ValueError(msg_0)
    elif action == 'assert_hidden':
        if locator.is_visible(timeout=timeout):
            msg_0 = 'Expected element is visible.'
            raise ValueError(msg_0)
    elif action == 'assert_enabled':
        if not locator.is_enabled(timeout=timeout):
            msg_0 = 'Expected element is disabled.'
            raise ValueError(msg_0)
    elif action == 'assert_text':
        expected_text = str(runtime.resolve(step['expected']))
        if locator.inner_text(timeout=timeout) != expected_text:
            msg_0 = 'Element text does not match the expected value.'
            raise ValueError(msg_0)
    elif action == 'assert_url':
        expected_url = str(runtime.resolve(step['expected']))
        if page.url != expected_url:
            msg_0 = 'Current URL does not match the expected value.'
            raise ValueError(msg_0)
    elif action == 'assert_attribute':
        expected_attribute = str(runtime.resolve(step['expected']))
        if locator.get_attribute(step['attribute'], timeout=timeout) != expected_attribute:
            msg_0 = 'Element attribute does not match the expected value.'
            raise ValueError(msg_0)
    elif action == 'extract_text':
        runtime.output_values[step['output']] = locator.inner_text(timeout=timeout)
    elif action == 'extract_attribute':
        value = locator.get_attribute(step['attribute'], timeout=timeout)
        runtime.output_values[step['output']] = value or ''
    elif action in {'download', 'wait_for_download'}:
        with page.expect_download(timeout=timeout) as download_info:
            locator.click(timeout=timeout)
        download = download_info.value
        runtime.output_values[step['output']] = str(download.path() or '')
    else:
        msg_0 = f'Unsupported action: {action}'
        raise ValueError(msg_0)


def _click_first_visible(page: Page, step: dict[str, Any], timeout: int) -> None:
    """Click the first visible accessible-name variant or selector."""
    selector = step.get('selector')
    if selector:
        locator = page.locator(selector).first
        if locator.is_visible(timeout=min(timeout, 2000)):
            locator.click(timeout=timeout)
        return
    target = step.get('target')
    if not isinstance(target, dict):
        msg = 'The step requires a selector or target.'
        raise TypeError(msg)
    role = target.get('role')
    names = target.get('names')
    if not role or not isinstance(names, list):
        msg_0 = 'The target must define an accessible role and names.'
        raise ValueError(msg_0)
    for name in names:
        locator = page.get_by_role(role, name=name, exact=True).first
        if locator.is_visible(timeout=min(timeout, 1000)):
            locator.click(timeout=timeout)
            return


def _get_locator(page: Page, step: dict[str, Any]) -> Locator:
    """Build a Playwright locator from a selector or accessible-role target."""
    selector = step.get('selector')
    if selector:
        return page.locator(selector).first
    target = step.get('target')
    if not isinstance(target, dict):
        msg = 'The step requires a selector or target.'
        raise TypeError(msg)
    role = target.get('role')
    names = target.get('names')
    if role and isinstance(names, list) and names:
        return page.get_by_role(role, name=names[0], exact=True).first
    msg_0 = 'The target must define an accessible role and at least one name.'
    raise ValueError(msg_0)


def _build_target_url(base_url: str, profile: dict[str, Any], step: dict[str, Any]) -> str:
    """Join a configured device base URL and a fixed named profile path."""
    path_ref = step['path_ref']
    path = profile['paths'][path_ref]
    normalized_base = f'{base_url.rstrip("/")}/'
    return urljoin(normalized_base, path.lstrip('/'))


def _assert_same_origin(base_url: str, target_url: str) -> None:
    """Reject redirects to another scheme, host, or port."""
    base = urlsplit(base_url)
    target = urlsplit(target_url)
    if (base.scheme, base.hostname, base.port) != (target.scheme, target.hostname, target.port):
        msg = 'The device redirected the browser outside the configured origin.'
        raise ValueError(msg)


def _verify_tls_fingerprint(base_url: str, expected_fingerprint: str) -> None:
    """Compare the live TLS endpoint certificate with an expected SHA-256 fingerprint."""
    split = urlsplit(base_url)
    if split.scheme != 'https' or split.hostname is None:
        msg = 'TLS fingerprint verification requires an HTTPS base URL.'
        raise ValueError(msg)
    port = split.port or 443
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((split.hostname, port), timeout=10) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=split.hostname) as tls_socket:
            certificate_der = tls_socket.getpeercert(binary_form=True)
    actual_fingerprint = hashlib.sha256(certificate_der).hexdigest()
    if _normalize_fingerprint(actual_fingerprint) != _normalize_fingerprint(expected_fingerprint):
        msg = 'The live TLS certificate fingerprint does not match the candidate certificate.'
        raise ValueError(msg)


def _normalize_fingerprint(fingerprint: str) -> str:
    """Normalize hexadecimal certificate fingerprints for comparison."""
    return re.sub(r'[^0-9a-fA-F]', '', fingerprint).lower()


def _sanitized_step_message(step: dict[str, Any], *, success: bool) -> str:
    """Return a step message that never includes resolved values or artifacts."""
    result = 'completed' if success else 'failed'
    sensitive_suffix = ' Sensitive values were redacted.' if step.get('sensitive') else ''
    return f'Action {step["action"]} {result}.{sensitive_suffix}'
