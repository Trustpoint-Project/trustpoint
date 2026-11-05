(workflow-engine)=

# Workflow engine

This page covers authoring, operating, and extending Trustpoint's WorkflowV2
implementation (`workflows2`). Workflows automate approval decisions, HTTP calls,
email, and Trustpoint notifications around devices and certificate requests.

## Authoring model

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

## Triggers and scope

The built-in registry exposes these production triggers:

| Event group | `trigger.on` values | Event context |
| --- | --- | --- |
| Device lifecycle | `device.created`, `device.updated`, `device.deleted` | `event.device`, `event.source`; updates also contain `before`, `after`, and `changes` under `device`. |
| Certificate lifecycle | `certificate.issued`, `certificate.revoked` | `event.certificate`, `event.device`, `event.source`. |
| CMP requests | `cmp.initialization`, `cmp.certification`, `cmp.keyupdate`, `cmp.certconf` | `event.cmp`, `event.device`, `event.source`. |
| EST enrollment | `est.simpleenroll`, `est.simplereenroll` | `event.est`, `event.device`, `event.source`. |
| REST enrollment | `rest.enroll`, `rest.reenroll` | `event.rest`, `event.device`, `event.source`. |

`workflows2.test` is an internal test trigger. SCEP has no built-in enrollment
trigger. Lifecycle triggers allow automation steps; request triggers also allow
`approval`, except during `after_issuance`.

`trigger.sources.trustpoint: true` matches all sources. Otherwise, at least one
of `ca_ids`, `domain_ids`, or `device_ids` must be nonempty. A match in **any** of
these lists is sufficient; the lists are not combined with AND. CA and domain
IDs are integers, while device IDs are strings. In contrast, every condition in
`apply` must match. Source filtering and `apply` run before an instance is created.

The editor's context catalog lists the supported paths for the selected trigger.
Enrollment context includes the requested profile at `event.cmp.cert_profile`,
`event.est.cert_profile`, or `event.rest.cert_profile`. EST and REST events also
include the CSR PEM and its fingerprint. CMP uses the encoded request body for
its fingerprint. Do not assume an arbitrary `event.meta` namespace exists.

Certificate lifecycle `event.certificate.serial_number` is the certificate's
assigned serial number. The post-issuance enrollment subject serial number is a
separate field described under [Effective enrollment certificate attributes](#effective-enrollment-certificate-attributes).

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
| `timed_out` | An approval timeout ended the workflow. | None. | Fail. |
| `stopped` | An operator or workflow intentionally stopped execution. | None. | Fail. |
| `cancelled` | An operator cancelled the run or instance. | None. | Fail. |

Important:

- `error` is not final. It stays visible in Waiting until an operator resumes or stops it.
- `stopped` is final, but keeps `status_reason` and `status_message` so a stopped-after-error workflow still shows the error context.
- `finished` only means there is no more workflow work to do. Use `approved`, `rejected`, `timed_out`, or `stopped` when the end state itself is the business result.

### Enrollment decisions and request locks

A trigger emission groups matching definitions into a run. Each definition has
its own instance, and all matching enrollment workflows must permit continuation.
The request decision also checks stored approvals: a rejected approval rejects
the request, and an expired approval fails it, even if later steps change the
instance status. Pending approvals keep a request waiting.

Request fingerprints provide idempotency keys, allowing repeated requests or polls
to reuse a run. Successful requester-visible delivery can release the key
through `request/workflow2_issuance.py`. For terminal runs that still hold a key,
**Allow same request again** releases it manually without changing the old result.
An identical request can then create a new run. The Runs page displays locked,
released, and manually released states.

### Operator views

- **Definitions:** create, edit, enable, and disable definitions; their names come
  from YAML `name`.
- **Runs:** inspect events, source snapshots, instances, results, and request locks;
  filter by status, trigger, and lock state.
- **Waiting / Approvals:** resolve pending decisions and inspect paused or errored
  instances. Resume retries the stored current step; Stop ends the instance.

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
without demo data installs none. Setup imports YAML definitions only; it does not
start executions. All demo workflows start disabled and must be enabled explicitly.
Repeating setup preserves existing definitions, including renamed, disabled, or
edited examples.

| Workflow | Initial state | Behavior |
| --- | --- | --- |
| Enrollment approval | Disabled | CMP initialization waits for approval; rejection denies enrollment and one hour without a decision times out. |
| Conditional enrollment approval | Disabled | CMP initialization with `tls_client` is approved automatically; other profiles wait for approval. |
| Issued certificate email | Disabled | Emails final certificate attributes after CMP initialization issuance. |
| Final certificate webhook | Disabled | Posts final certificate attributes after CMP initialization issuance and branches on the HTTP response status. |

Open **Workflows**, select a `[Demo]` definition, and inspect its YAML and flow
graph. Each YAML file starts with comments explaining its inputs and behavior.
The normal Save & Compile formatter removes YAML comments.
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

Email and webhook examples use the services in `docker-compose.demo.yml`. Start
Trustpoint first so its shared Docker network exists, then start the demo services:

```sh
docker compose -p trustpoint-demo -f docker-compose.demo.yml up -d
```

Use the same `TRUSTPOINT_NETWORK_NAME` for both Compose projects if you override
the default `trustpoint-net`. The workflow worker must also join this network.

In **Management > Settings > SMTP Email**, enable SMTP and save these Mailpit settings:

| Setting | Value |
| --- | --- |
| Host | `mailpit` |
| Port | `1025` |
| TLS / SSL | Both disabled |
| Username / password | Both blank |
| Sender | `trustpoint@trustpoint.example` |

The email workflow sends to `operator@trustpoint.example`; view captured messages
at `http://localhost:8025`. The webhook already posts to
`http://webhook-echo:8080/trustpoint/certificates`. Inspect its requests with:

```sh
docker compose -p trustpoint-demo -f docker-compose.demo.yml logs -f webhook-echo
```

For Trustpoint running directly on the host, use SMTP host `localhost` and webhook
URL `http://localhost:8081/trustpoint/certificates` instead. If you override
`MAILPIT_SMTP_PORT`, `MAILPIT_UI_PORT`, or `WEBHOOK_ECHO_PORT`, use those ports for
host access; container-to-container ports stay `1025`, `8025`, and `8080`.

Enable the desired workflow and **Save & Compile** before submitting an enrollment.
Email and webhook notifications run after the matching approval workflows permit
issuance. Both examples initially remain disabled. Reinitialization preserves
existing definitions, so apply these values in the editor for previously imported
examples.

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

- `cmp.initialization`, `cmp.certification`, and `cmp.keyupdate`
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
      url: http://webhook-echo:8080/trustpoint/certificates
      headers:
        Content-Type: application/json
      body:
        effective_subject_serial_number: ${event.request.subject.serial_number}
        stored_device_serial_number: ${event.device.serial_number}
        operation: ${event.cmp.operation}
  flow: []
```

The URL targets `webhook-echo` from the demo Compose setup described above.
Replace it when using a different receiver.
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
    x-device-id: ${event.device.id}
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
- Without a timeout route, expired approvals end as `timed_out`.
- `approved_outcome`, `rejected_outcome`, and `timeout_outcome` can customize outcome names.
- A routed timeout branch must reach an explicit `set_status` result of `rejected`,
  `timed_out`, `stopped`, or `paused`. Implicit completion or `approved` is rejected
  by the compiler. The recorded expired approval still prevents enrollment from
  continuing.

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

Every step must be reachable from `workflow.start`. Linear steps may have one
outgoing linear edge; `logic` needs a route for every declared outcome. Approval
routes follow the rules above. Terminal `set_status` steps cannot have outgoing
edges, while `paused` requires one linear edge to its resume point. There are no
special `$end` or `$reject` target tokens.

To end a branch, omit the outgoing transition. To end a branch with a non-finished
result, use `set_status`.

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

`compare.op` supports `==`, `!=`, `<`, `<=`, `>`, and `>=`.
`and` and `or` require nonempty condition lists.

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

Open the guide with `Ctrl+K` (`Cmd+K` on macOS).

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

Every `logic` outcome must have a matching `workflow.flow` entry. Approval
outcomes may omit routes and use the built-in terminal decisions.

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

## Execution and worker operation

`management.models.workflows2.WorkflowExecutionConfig` stores the execution mode:

| Mode | Behavior |
| --- | --- |
| `auto` (default) | Use the worker when a recent heartbeat exists; otherwise drain jobs inline. |
| `inline` | Enqueue jobs and drain them in the current process. Within a transaction, drain after commit. |
| `worker` | Enqueue jobs for the dedicated worker. |

All modes use the same database job queue and worker semantics. Inline mode does
not bypass the queue. The default worker-liveness threshold is 30 seconds.
Run the worker from the repository root:

```sh
python trustpoint/manage.py workflows2_worker
```

| Option | Default | Purpose |
| --- | --- | --- |
| `--id` | Hostname | Worker identity. |
| `--lease-seconds` | 30 | Job lease duration; `--lease` is its alias. |
| `--limit` | 10 | Jobs per tick; `--batch` is its alias. |
| `--sleep` | 1.0 | Seconds between ticks. |
| `--wait-migrations-seconds` | 180 | Wait for required tables; `0` waits indefinitely. |
| `--once` | Off | Run one tick and exit. |

The command writes worker-presence heartbeats every five seconds. A separate
per-job heartbeat renews a running job's lease at half the lease duration, with
a minimum interval of one second; it is disabled on SQLite and during inline
draining. PostgreSQL workers coordinate claims with row locking and skip locked
rows. SQLite uses a best-effort fallback.

An expired job lease marks the job failed and pauses an eligible instance for
operator review. It does not automatically replay external side effects. Runtime
step exceptions record an `error` state at the current step, which an operator
can resume or stop. Job infrastructure failures can retry when the job's
`max_attempts` allows it; the model defaults to zero retries. Do not assume
webhook failures receive automatic retries. Webhook HTTP error status codes are
returned as data; use capture plus `logic` to handle them. Transport exceptions
enter the runtime error path. External receivers should tolerate a repeated call
when an operator retries after an uncertain result.

The workflow worker is separate from Django-Q2's maintenance scheduler. Workflow
steps do not directly issue, revoke, or renew certificates: the enrollment
pipeline performs those operations after any pre-issuance gates permit them.
There are no generic `pki.*` step types or approval-group settings.

### Troubleshooting

| Symptom | Check |
| --- | --- |
| Work remains queued | Execution mode, worker process, heartbeat freshness, and database connection. |
| Instance shows `error` | Step-run error and event snapshot, SMTP/HTTP destination, then Resume or Stop. |
| Instance paused after lease expiry | Worker crash or lease/heartbeat problem; inspect external side effects before resuming. |
| Approval has expired | Waiting / Approvals refresh and resolution paths apply expiration handling; it is not a dedicated Q2 timeout task. |
| Enrollment still waits after an approval | Other instances and pending approvals in the same run. |
| Workflow never matches | Enabled flags, trigger phase, source filters, and `apply` conditions. |

## Implementation and extension

All paths below are relative to `trustpoint/workflows2/` unless explicitly prefixed
with a repository path. This section describes the code implementing the authoring
and execution behavior above.

### Compilation and persistence

`WorkflowDefinitionService` in `services/definitions.py` formats YAML, compiles it,
and saves `Workflow2Definition`. `compile_workflow_yaml` in
`compiler/compiler.py` loads the document, applies `SchemaLinter`, compiles
conditions, templates, expressions, steps, and transitions, and validates trigger
policy, flow completeness, reachability, and variable availability. The IR stores
`workflow.transitions` derived from YAML `workflow.flow`, plus source/IR hashes
and a compiler version in `meta`.

| Module | Responsibility |
| --- | --- |
| `compiler/lint.py` | Reject unknown schema keys and step types. |
| `compiler/yaml_loader.py`, `compiler/yaml_format.py` | YAML loading and canonical formatting. |
| `compiler/expr.py`, `compiler/templates.py` | Allowed expression roots/functions and `${...}` templates. |
| `compiler/conditions.py` | Compile condition trees. |
| `compiler/hashing.py` | Stable source and IR hashing. |
| `events/registry.py`, `events/builtin.py` | Register trigger metadata. |
| `events/context_catalog.py`, `events/policies.py` | Advertise event context and allowed steps. |
| `catalog/steps.py`, `catalog/build.py` | Step-field and expression metadata consumed by the editor. |

Top-level keys are `schema`, `name`, `enabled`, `trigger`, `apply`, and `workflow`.
There is no `description` field; use comments for authoring notes. The demo loader
in `services/demo.py` compiles YAML from `demo_workflows/` and preserves its source
comments on initial import. UUIDs derived from filenames allow reruns to skip
existing definitions even after users rename them. The only initialization hook
is the explicit `pki` command `add_domains_and_devices`.

### Durable execution

| Model in `models.py` | Responsibility |
| --- | --- |
| `Workflow2Definition` | YAML, compiled IR, hashes, enabled flag, and trigger index. |
| `Workflow2Run` | Event emission, source snapshot, aggregate status, and idempotency metadata. |
| `Workflow2Instance` | One definition's event/vars, current step, status, and reason/message. |
| `Workflow2StepRun` | Step execution audit records. |
| `Workflow2Approval` | Pending/approved/rejected/expired decision, expiry, actor, and comment. |
| `Workflow2Job` | Queued/running/done/failed/cancelled work, leases, attempts, and errors. |
| `Workflow2WorkerHeartbeat` | Worker presence. |
| `Workflow2DefinitionUiState` | Layout snapshot model; the current draft editor computes its layout client-side. |

`services/dispatch.py` selects enabled matching definitions, reuses idempotent
runs when appropriate, persists runs and instances, and enqueues jobs.
`services/worker.py` claims and executes jobs, normally advancing one step per job.
`services/runtime.py` checkpoints instance progress, records step runs and
approvals, and aggregates run status. `services/transitions.py` centralizes state
changes; `services/request_decision.py` translates them into enrollment decisions.

`engine/executor.py` evaluates steps against the `RuntimeContext` event and vars.
`engine/eval.py` evaluates conditions and expressions. `engine/adapters.py`
isolates email, HTTP, and Trustpoint notification side effects. Tests can inject
adapter doubles without contacting external services.

### Enrollment integration and final certificate snapshots

`trustpoint/request/workflows2_handler.py` builds protocol event payloads.
`trustpoint/request/enrollment.py` preserves the pre-issuance decision gate and
calls `Workflow2CertificateRequestHandler.handle_issued` after successful
processing. CMP polling calls the same handler on its finalized replay context.
`events/payloads.py:build_enrollment_request_snapshot` extracts the supported
subject/SAN fields from the final `cryptography.x509.Certificate`.

The handler captures fresh JSON before registering a transaction `on_commit`
callback. Post-issuance dispatch uses `issued:<certificate SHA-256 fingerprint>`
as a separate idempotency key. Both the run and its instances persist the event
snapshot. Capture/dispatch failures are logged without changing the pre-issuance
authorization outcome or reversing issuance. This dispatch is best effort: there
is no transactional outbox protecting the interval between commit and dispatch.

### Editor and HTTP interfaces

The Django page is `trustpoint/templates/workflows2/definition_editor.html`.
`frontend/src/workflow_editor/index.js` boots the workspace. The frontend parses
raw YAML into a tolerant draft graph; graph and guide actions mutate the YAML
through shared document operations. Backend compilation remains authoritative.

| Frontend directory under `frontend/src/workflow_editor/` | Responsibility |
| --- | --- |
| `page/`, `editor/` | Workspace, DOM wiring, and CodeMirror controller. |
| `document/`, `document/operations/` | YAML mutations, flow/condition helpers, variable availability. |
| `graph/` | Draft parsing, automatic layout, SVG rendering, canvas interactions, and overlays. |
| `guide/` | Semantic context, catalog-driven guide rendering, and insertion actions. |
| `logic/`, `steps/`, `variables/` | Structured condition/step controls and scoped runtime picker. |
| `ui/`, `shared/` | Drawer, graph expansion, issues panel, DOM, and HTTP utilities. |

`urls.py` and `views/` expose the following APIs under `/workflows2/`:

| Path | Purpose |
| --- | --- |
| `api/triggers/` | Trigger catalog. |
| `api/context-catalog/` | Event, step, expression, and DSL metadata. |
| `api/graph-from-yaml/` | Compile supplied YAML to a graph without saving. |
| `api/definitions/<uuid>/graph/` | Graph derived from stored IR. |

`services/graph.py` adapts IR for backend graph consumers; it does not replace the
client-side draft graph. Definition views in `views/definitions.py` save through
the definition service. Runtime controls are in `views/runs.py`,
`views/instances.py`, and `views/approvals.py`.

### Extending the engine

Keep YAML as the only authoring source, preserve tolerant draft rendering, and
keep frontend `document/variable_availability.js` consistent with backend
`WorkflowCompiler._compute_available_vars_before_step`. A later `compute`
assignment can use an earlier assignment in the same step; `set` cannot.

| Extension | Code to update |
| --- | --- |
| Step type | `compiler/step_types.py`, `compiler/lint.py`, `compiler/compiler.py`, `catalog/steps.py`, `engine/executor.py`; variable analysis and structured controls when relevant. |
| Expression function | `compiler/expr.py` function metadata/arity, `engine/eval.py`, and frontend `document/expression_insertions.js`. |
| Condition operator | `compiler/conditions.py`, `engine/eval.py`, frontend condition operations and controls. |
| Trigger | `events/triggers.py`, registry bootstrapping, context metadata, policies, and the integration that actually emits it. |

Update documentation and test both compiler rejection and runtime behavior for an
extension. Catalog registration alone does not cause application events to fire.

### Verification commands

From the repository root:

```sh
python -m pytest trustpoint/workflows2/tests trustpoint/request/tests/test_workflows2_handler.py trustpoint/request/tests/test_workflow2_issuance.py
```

The tests cover compilation, expression evaluation, dispatch, persistence,
approvals, worker/crash recovery, protocol enrollment, and the demo definitions.
`tests/test_enrollment_events.py` also compiles the complete final-certificate
webhook example in this page. Its local HTTP integration test needs permission to
bind a loopback socket.

Rebuild the browser bundle after frontend changes:

```sh
cd trustpoint/workflows2/frontend
npm ci
npm run build
```

`frontend/build.mjs` writes `trustpoint/static/js/workflows2/editor_bundle.js`.
Build the published documentation from the repository root with:

```sh
python -m sphinx -b html docs/source /tmp/trustpoint-docs-html
```
