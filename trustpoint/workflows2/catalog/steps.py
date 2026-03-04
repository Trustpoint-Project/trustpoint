# workflows2/catalog/steps.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

InsertKind = Literal["inline", "block"]


@dataclass(frozen=True)
class StepField:
    key: str               # e.g. "url" or "headers"
    title: str
    description: str
    insert_kind: InsertKind
    snippet: str           # inserted at cursor (usually as YAML line(s))

    # ✅ NEW
    required: bool = False


@dataclass(frozen=True)
class StepSpec:
    type: str
    title: str
    description: str
    category: str          # "step" | "terminal"
    block_snippet: str     # a full step block to insert under workflow.steps
    fields: list[StepField]


def step_specs() -> list[StepSpec]:
    return [
        StepSpec(
            type="logic",
            title="Logic routing",
            description="Evaluate cases and return an outcome string.",
            category="step",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: logic\n"
                "  title: \"__CURSOR__\"\n"
                "  cases:\n"
                "    - when:\n"
                "        compare:\n"
                "          left: ${vars.status}\n"
                "          op: \"==\"\n"
                "          right: 200\n"
                "      outcome: ok\n"
                "  default: fail\n"
            ),
            fields=[
                StepField(
                    key="case",
                    title="case",
                    description="Add another case.",
                    insert_kind="block",
                    snippet=(
                        "- when:\n"
                        "    compare:\n"
                        "      left: ${vars.__CURSOR__}\n"
                        "      op: \"==\"\n"
                        "      right: 0\n"
                        "  outcome: ok\n"
                    ),
                    required=True,
                ),
                StepField(
                    key="default",
                    title="default outcome",
                    description="Set default outcome.",
                    insert_kind="inline",
                    snippet="fail",
                    required=True,
                ),
            ],
        ),
        StepSpec(
            type="webhook",
            title="Webhook",
            description="HTTP request via adapter.",
            category="step",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: webhook\n"
                "  title: \"__CURSOR__\"\n"
                "  method: POST\n"
                "  url: \"https://example.com/api\"\n"
                "  headers: {}\n"
                "  body: null\n"
                "  timeout_seconds: 10\n"
                "  capture:\n"
                "    status_code: vars.http_status\n"
                "    body: vars.http_body\n"
            ),
            fields=[
                StepField("method", "method", "HTTP method.", "block", "method: POST\n", required=True),
                StepField("url", "url", "Request URL (templated).", "block", "url: \"__CURSOR__\"\n", required=True),

                # Optional extras
                StepField(
                    "headers",
                    "headers",
                    "Request headers map.",
                    "block",
                    "headers:\n  x-request-id: \"${event.meta.request_id}\"\n",
                    required=False,
                ),
                StepField(
                    "body",
                    "body",
                    "Request body (any YAML).",
                    "block",
                    "body:\n  __CURSOR__: \"value\"\n",
                    required=False,
                ),
                StepField("timeout_seconds", "timeout_seconds", "Timeout in seconds.", "block", "timeout_seconds: 10\n", required=False),
                StepField("capture", "capture", "Capture response fields into vars.", "block", "capture:\n  status_code: vars.http_status\n", required=False),
            ],
        ),
        StepSpec(
            type="email",
            title="Email",
            description="Send an email via adapter.",
            category="step",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: email\n"
                "  title: \"__CURSOR__\"\n"
                "  to:\n"
                "    - \"test@example.com\"\n"
                "  cc: []\n"
                "  bcc: []\n"
                "  subject: \"Hello ${vars.user}\"\n"
                "  body: \"Hi ${vars.user}\\n\"\n"
            ),
            fields=[
                # ✅ REQUIRED
                StepField("to", "to", "Recipients list.", "block", "to:\n  - \"__CURSOR__@example.com\"\n", required=True),
                StepField("subject", "subject", "Email subject (templated).", "inline", "\"__CURSOR__\"", required=True),
                StepField("body", "body", "Email body (templated).", "block", "body: |\n  __CURSOR__\n", required=True),

                # ✅ OPTIONAL (you asked for these)
                StepField("cc", "cc", "CC recipients list.", "block", "cc:\n  - \"__CURSOR__@example.com\"\n", required=False),
                StepField("bcc", "bcc", "BCC recipients list.", "block", "bcc:\n  - \"__CURSOR__@example.com\"\n", required=False),
            ],
        ),
        StepSpec(
            type="approval",
            title="Approval",
            description="Pause until external approval decision.",
            category="step",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: approval\n"
                "  title: \"__CURSOR__\"\n"
                "  approved_outcome: approved\n"
                "  rejected_outcome: rejected\n"
                "  timeout_seconds: 3600\n"
            ),
            fields=[
                StepField("approved_outcome", "approved_outcome", "Outcome for approve.", "inline", "approved", required=True),
                StepField("rejected_outcome", "rejected_outcome", "Outcome for reject.", "inline", "rejected", required=True),
                StepField("timeout_seconds", "timeout_seconds", "Optional timeout.", "inline", "3600", required=False),
            ],
        ),
        StepSpec(
            type="set",
            title="Set vars",
            description="Write literal/templated values into vars.",
            category="step",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: set\n"
                "  title: \"__CURSOR__\"\n"
                "  vars:\n"
                "    foo: \"bar\"\n"
            ),
            fields=[
                StepField(
                    key="vars",
                    title="vars map",
                    description="Add/replace vars mapping.",
                    insert_kind="block",
                    snippet="vars:\n  __CURSOR__: \"value\"\n",
                    required=True,
                ),
            ],
        ),
        StepSpec(
            type="compute",
            title="Compute vars",
            description="Assign vars via safe expressions/ops.",
            category="step",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: compute\n"
                "  title: \"__CURSOR__\"\n"
                "  set:\n"
                "    vars.total: ${add(vars.a, vars.b)}\n"
            ),
            fields=[
                StepField(
                    key="set",
                    title="set assignment",
                    description="Add a vars.<name> assignment.",
                    insert_kind="block",
                    snippet="set:\n  vars.__CURSOR__: ${add(vars.a, 1)}\n",
                    required=True,
                ),
            ],
        ),

        # terminals
        StepSpec(
            type="stop",
            title="Stop",
            description="Terminal: stopped.",
            category="terminal",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: stop\n"
                "  reason: \"__CURSOR__\"\n"
            ),
            fields=[],
        ),
        StepSpec(
            type="succeed",
            title="Succeed",
            description="Terminal: succeeded.",
            category="terminal",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: succeed\n"
                "  message: \"__CURSOR__\"\n"
            ),
            fields=[],
        ),
        StepSpec(
            type="fail",
            title="Fail",
            description="Terminal: failed.",
            category="terminal",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: fail\n"
                "  reason: \"__CURSOR__\"\n"
            ),
            fields=[],
        ),
        StepSpec(
            type="reject",
            title="Reject",
            description="Terminal: rejected.",
            category="terminal",
            block_snippet=(
                "__STEP_NAME__:\n"
                "  type: reject\n"
                "  reason: \"__CURSOR__\"\n"
            ),
            fields=[],
        ),
    ]
