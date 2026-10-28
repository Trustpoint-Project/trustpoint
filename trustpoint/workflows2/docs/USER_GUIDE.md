# Workflows 2 User Guide

## What Workflows 2 Is

Workflows 2 is a YAML-first automation system.

You author a workflow definition in YAML, and the editor gives you three coordinated helpers around it:

- a YAML editor for direct authoring
- a draft graph editor for structural editing and visualization
- a context-aware guide drawer for inserting documented DSL pieces

YAML stays the source of truth. The graph and guide never replace it.

The saved workflow display name is derived from the top-level YAML `name:` field.
Edit the YAML name when you want to rename a workflow.

## The Mental Model

A workflow has five main parts:

1. `trigger`
   Chooses which event starts the workflow.
2. `apply`
   Optional preconditions. Every item in `apply` must match.
3. `workflow.start`
   The first step to run.
4. `workflow.steps`
   Named step definitions.
5. `workflow.flow`
   Transitions between steps.

At runtime you can read:

- `event.*`
- `vars.*`

`event` is read-only runtime input.

`vars` is mutable workflow state written by steps such as `set`, `compute`, and `webhook.capture`.

## Lifecycle States

Workflow instance and run states use the same vocabulary where possible.

| State | Meaning | Operator action | Request decision |
| --- | --- | --- | --- |
| `queued` | Work is waiting for a worker or inline drain. | Wait. | Wait. |
| `running` | Work is currently executing. | Wait. | Wait. |
| `awaiting` | An approval step is waiting for a decision. | Approve or reject. | Wait. |
| `paused` | Execution stopped safely and can resume from the stored next step. | Resume or stop. | Wait. |
| `error` | Execution hit a retryable runtime error. | Resume or stop. | Wait. |
| `finished` | The workflow reached the end of a branch without an explicit business result. | None. | Continue. |
| `approved` | The workflow ended with an approved business result. | None. | Continue. |
| `rejected` | The workflow ended with a rejected business result. | None. | Reject. |
| `timed_out` | An approval or workflow timeout ended the workflow. | None. | Fail. |
| `stopped` | An operator or workflow intentionally stopped execution. | None. | Fail. |
| `cancelled` | An operator cancelled the run or instance. | None. | Fail. |

Important:

- `error` is not final. It stays visible in Waiting until an operator resumes or stops it.
- `stopped` is final, but keeps `status_reason` and `status_message` so a stopped-after-error workflow still shows the error context.
- `finished` only means there is no more workflow work to do. Use `approved`, `rejected`, `timed_out`, or `stopped` when the end state itself is the business result.

## Minimal Example

```yaml
schema: trustpoint.workflow.v2
name: Device created notification
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []

apply:
  - exists: ${event.device}

workflow:
  start: notify

  steps:
    notify:
      type: email
      title: Send email
      to:
        - ops@example.com
      subject: New device ${event.device.common_name}
      body: |
        Device ID: ${event.device.id}

  flow: []
```

## Demo workflows

Explicit demo-data setup installs four editable `[Demo]` workflows through the
existing `add_domains_and_devices` command. The setup wizard's demo-data option,
`TP_INJECT_DEMO_DATA`, and `reset_db --add` all use this path. Normal initialization
without demo data installs none. Setup imports YAML definitions only; it does not start executions. Repeating setup preserves existing definitions,
including renamed, disabled, or edited examples.

| Workflow | Initial state | Behavior |
| --- | --- | --- |
| Enrollment approval | Enabled | CMP initialization waits for approval; rejection denies enrollment and one hour without a decision times out. |
| Conditional enrollment approval | Enabled | CMP initialization with `tls_client` is approved automatically; other profiles wait for approval. |
| Issued certificate email | Disabled | Emails final certificate attributes after CMP initialization issuance. |
| Final certificate webhook | Disabled | Posts final certificate attributes after CMP initialization issuance and branches on the HTTP response status. |

Open **Workflows**, select a `[Demo]` definition, and inspect its YAML and flow
graph. Each YAML file starts with comments explaining its inputs and behavior.
The existing editor generates the graph layout automatically.

Fixtures live directly in `workflows2/demo_workflows/*.yaml`. The loader imports
the YAML files through the existing compiler; filenames provide stable workflow
identities. All examples use `cmp.initialization` with `trustpoint: true`, so they
apply across all domains. No manifest, placeholders, or editor changes are needed.

To execute an example, use a device with CMP enrollment configured in any domain.
Use the device's enrollment help for credentials and request commands. Request an
application certificate using the existing `tls_client` profile. For conditional
approval, request `tls_server` to take the manual branch instead. Normal device,
authentication, CA, and profile checks still apply. Resolve pending approvals in
the workflow approval queue, then use CMP polling as instructed by the response.
The normal inline/worker execution setting applies; worker mode requires the
existing `workflows2_worker` process.

Both approval examples initially match the same CMP initialization requests. All
matching workflows must permit issuance, so disable the manual approval example
when trying the conditional example's automatic path on its own.

For email, configure SMTP in Trustpoint and replace `operator@example.invalid`
with a real recipient. For the webhook, replace the reserved `.invalid` URL with
your JSON receiver. Enable the chosen definition and **Save & Compile** before
submitting an enrollment. Email and webhook notifications run after the matching approval
workflows have permitted issuance. No external mail or HTTP destination is contacted
by the initial disabled examples.

The email and webhook use the **final issued certificate after profile processing**.
For example, a final subject containing `serialNumber=SN123456` produces
`"subject_serial_number": "SN123456"` in the webhook body, even if the original CSR
or stored device has a different value. If the final subject lacks this attribute,
the body contains `"subject_serial_number": ""`. This is the subject serialNumber
(OID 2.5.4.5), separate from the certificate's CA-assigned integer serial number.
Use a profile that permits the requested subject serialNumber, such as the default
`tls_client` profile, to preserve it through issuance.

The webhook captures HTTP status in `vars.http_status`. A 2xx response finishes the
workflow; other HTTP responses stop it with an explanatory message. Transport
failures enter the engine's retryable error state. Both email and webhook run in
`after_issuance`, so notification failure cannot undo issuance or block delivery.

## Effective enrollment certificate attributes

The existing enrollment triggers support `trigger.phase: after_issuance`:

- `cmp.initialization` and `cmp.certification`
- `est.simpleenroll` and `est.simplereenroll`
- `rest.enroll` and `rest.reenroll` (including enrollment through the management API)

Set this phase explicitly for notifications about a successfully issued certificate.
Omitting `phase` retains the existing `before_issuance` behavior, including approval,
rejection, and request gating. Those earlier events do not contain `request`.
An existing pre-issuance workflow must opt into `after_issuance` to use the effective
certificate fields. Approval steps are unavailable in this phase; notification
failure cannot reverse issuance or block delivery. Trigger names and source filters
are unchanged. SCEP is not supported by these workflow triggers.

Post-issuance events retain the existing `device`, `source`, and protocol-specific
(`cmp`, `est`, or `rest`) sections, and add:

```json
{
  "phase": "after_issuance",
  "request": {
    "subject": {
      "common_name": "Trustpoint-Domain-Credential",
      "serial_number": "SN123456",
      "organization": null,
      "organizational_unit": null,
      "country": null,
      "state_or_province": null,
      "locality": null
    },
    "subject_alternative_names": {
      "dns_names": ["plc.example.com"],
      "ip_addresses": ["192.168.1.10"],
      "uris": [],
      "email_addresses": []
    }
  }
}
```

Despite its interface name, `request` contains attributes extracted from the final
issued X.509 certificate **after certificate profile processing**, including any
changes made by an upstream CA. It does not expose the original CSR or CRMF values.
`request.subject.serial_number` is the subject's serialNumber attribute (OID 2.5.4.5).
It is independent of the stored `device.serial_number` and of the certificate's
automatically assigned integer serial number.

Every listed subject key is a string or `null`; every SAN key is an array of strings
and is `[]` when absent. IP addresses use canonical string notation. For repeated
subject attributes, the first value in certificate subject order is selected,
matching credential saving's first-value convention. This simple view does not
preserve repeated RDNs, arbitrary OIDs, or unsupported SAN types.

Values are captured when issuance succeeds, before deferred dispatch. Dispatch
waits for the issuance transaction to commit, so failed or rolled-back issuance
does not emit a post-issuance event. The run and each workflow instance persist the
snapshot; later device or certificate changes do not affect delayed or retried
execution. CMP approval followed by polling uses the original enrollment operation.

Example forwarding the effective subject serial number:

```yaml
schema: trustpoint.workflow.v2
name: CMP Effective Subject Serial Number Webhook
enabled: true

trigger:
  on: cmp.initialization
  phase: after_issuance
  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []

workflow:
  start: forward_serial
  steps:
    forward_serial:
      type: webhook
      title: Forward effective certificate subject serial number
      method: POST
      url: https://example.invalid/cmp-audit
      headers:
        Content-Type: application/json
      body:
        effective_subject_serial_number: ${event.request.subject.serial_number}
        stored_device_serial_number: ${event.device.serial_number}
        operation: ${event.cmp.operation}
  flow: []
```

The URL is intentionally nonoperational. Replace it with your receiver.
The expression resolver renders `${...}` templates as strings; a `null` subject
value becomes an empty string in a templated webhook body. The persisted event
still contains JSON `null`. To send only when a serial number exists, add:

```yaml
apply:
  - exists: ${event.request.subject.serial_number}
```

## Supported Step Types

### `logic`

Evaluates ordered cases and returns an outcome string.

```yaml
route_status:
  type: logic
  cases:
    - when:
        compare:
          left: ${vars.http_status}
          op: ==
          right: 200
      outcome: ok
  default: fail
```

Notes:

- Supports nested `and`, `or`, `not`, `exists`, and `compare`.
- Every possible outcome must have a matching `workflow.flow` entry.

### `webhook`

Makes an HTTP request and can capture response data into workflow vars.

```yaml
call_api:
  type: webhook
  method: POST
  url: https://example.com/api/${event.device.serial_number}
  headers:
    x-request-id: ${event.meta.request_id}
  body:
    serial: ${event.device.serial_number}
  capture:
    vars.http_status: status_code
    vars.http_body: body
```

Capture sources:

- `status_code`
- `body`
- `headers`
- `headers.<name>`
- `body.<path>`

### `email`

Sends an email with templated subject and body.

```yaml
notify:
  type: email
  to:
    - ops@example.com
  subject: Device ${event.device.common_name}
  body: |
    Status: ${vars.status}
```

### `notification`

Creates a Trustpoint notification with templated custom text.

```yaml
create_notification:
  type: notification
  severity: warning
  source: device
  short: Device ${event.device.common_name} needs review
  long: |
    Device ID: ${event.device.id}
    Result: ${vars.result}
  initial_status: new
  event: workflow.device.review
  related:
    device_id: ${event.device.id}
```

Supported severities:

- `setup`
- `info`
- `warning`
- `critical`

Supported sources:

- `system`
- `device`
- `domain`
- `certificate`
- `issuing_ca`

Optional `related` keys:

- `device_id`
- `domain_id`
- `certificate_id`
- `issuing_ca_id`

### `set`

Writes literal or templated values into workflow vars.

```yaml
mark_ok:
  type: set
  vars:
    vars.result: ok
    vars.message: Status was ${vars.http_status}
```

Important:

- Prefer `set.vars` keys in `vars.<name>` form for consistency with webhook capture, compute, and references.
- Legacy plain keys are still accepted by the compiler, but the editor now writes `vars.<name>`.

### `set_status`

Sets the workflow instance status intentionally. Use this when the workflow itself has reached a business decision such as approved, rejected, stopped, paused, or timed out.

```yaml
reject_device:
  type: set_status
  status: rejected
  reason: policy_rejected
  message: Device ${event.device.common_name} did not pass policy review.
```

Supported statuses:

- `finished`
- `approved`
- `rejected`
- `timed_out`
- `stopped`
- `paused`

Important:

- `reason` is a short static value stored on the workflow instance.
- `message` is templated and shown on the instance detail page.
- `paused` must have one outgoing linear flow entry; that target becomes the next step after resume.
- Other `set_status` statuses are terminal and cannot have outgoing flow entries.
- `error` is reserved for retryable runtime failures with `status_reason: runtime_error`.

### `compute`

Writes workflow vars using safe expressions.

```yaml
compute_score:
  type: compute
  set:
    vars.score: ${add(vars.base_score, 1)}
```

You can also use YAML operator mappings:

```yaml
compute_score:
  type: compute
  set:
    vars.score:
      add:
        - ${vars.base_score}
        - 1
```

Important:

- `compute.set` targets must use `vars.<name>`.
- Within one compute step, later assignments may reference vars assigned earlier in the same `compute.set` block.

### `approval`

Pauses execution until an external approval decision is resolved.

```yaml
approval_gate:
  type: approval
  timeout_seconds: 3600
```

Notes:

- Approval outcomes default to `approved`, `rejected`, and `timed_out`.
- Approval outcomes can be routed in `workflow.flow`, but they do not have to be.
- If an approved approval has no route, the workflow instance ends as `approved`.
- If a rejected approval has no route, the workflow instance ends as `rejected`.
- Timed-out approvals end as `timed_out`.

## Flow Rules

Linear transition:

```yaml
- from: call_api
  to: mark_ok
```

Outcome-based transition:

```yaml
- from: route_status
  on: ok
  to: mark_ok
```

To end a branch, omit the outgoing transition. To end a branch with a non-finished result, use `set_status`.

```yaml
reject_device:
  type: set_status
  status: rejected
  reason: policy_rejected
  message: Device did not pass policy review.
```

## Conditions

Supported condition operators:

- `exists`
- `compare`
- `not`
- `and`
- `or`

Example:

```yaml
- and:
    - exists: ${vars.http_status}
    - compare:
        left: ${vars.http_status}
        op: ==
        right: 200
```

`apply` uses list semantics, so all items in the `apply:` list must match.

## Expressions

Expressions are written as `${...}`.

Allowed reference roots:

- `event.*`
- `vars.*`

Supported function families:

- numeric: `add`, `sub`, `mul`, `div`, `min`, `max`, `round`, `int`, `float`
- string: `str`, `lower`, `upper`, `concat`
- debug: `json`

Examples:

```yaml
${event.device.common_name}
${upper(event.device.common_name)}
${round(vars.score)}
${concat(vars.prefix, "-", vars.suffix)}
```

## Variable Availability Rules

This is one of the most important Workflow 2 rules.

A step may only rely on workflow vars that are guaranteed to exist on every incoming reachable path.

That means:

- a var created on only one branch is not safe at a later merge step
- unreachable steps do not count
- the graph and guide show the vars available before a step runs
- the compiler enforces the same rule when you save and compile

Also note the difference between `set` and `compute`:

- `set` renders the full mapping first, then writes values
- `compute` evaluates assignments in order, so later compute expressions can use earlier compute outputs from the same step

## Using the Editor

### YAML Editor

- YAML is always the source of truth.
- Save & Compile formats YAML canonically before saving.
- Undo/redo works inside the editor.

### Guide Drawer

Open the guide with `Ctrl+K`.

Use it to:

- inspect field requirements
- edit structured content for logic, webhook, compute, set, and set_status steps
- insert scoped variables and expression helpers

### Graph Editor

Use the graph to:

- preview incomplete workflows
- drag nodes
- create edges from node handles
- right-click a node or edge to edit it
- right-click empty canvas to add a step at the cursor
- delete the selected node or edge with `Delete` or `Backspace`
- close editors or menus with `Escape`

The graph stays available even if the workflow is incomplete. Problems show up in the issues panel instead of making the editor disappear.

### Issues Panel

The issues panel highlights:

- YAML syntax problems
- draft graph problems
- editor action errors
- compile errors after save

When possible, selecting an issue focuses the YAML editor at the relevant location.

## Common Compile Errors

### Unreachable step

Every step must be reachable from `workflow.start`.

### Missing outcome flow

Every `logic` or `approval` outcome must have a matching `workflow.flow` entry.

### Variable may not be initialized

You referenced `vars.<name>` before that var is guaranteed to exist.

### Unknown key or step type

The schema linter rejects unsupported keys and step types early.

### Wrong webhook capture format

Use:

```yaml
capture:
  vars.http_status: status_code
```

Do not use the older legacy capture shape.

## Authoring Advice

- Start with valid YAML and a simple linear flow.
- Add `logic` only after your base steps and vars are clear.
- Use the graph for structure and the guide for documented snippets.
- Use `compute` for actual expressions and `set` for direct templated values.
- Keep step ids stable; use `title` for a friendly label.
- If something looks odd in the graph, trust the YAML and the issues panel first.
