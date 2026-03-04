# TrustPoint Workflows v2 — Specification (SPEC.md)

This document is the **normative** specification for the TrustPoint Workflows v2 YAML format and its execution semantics.

- **Audience:** implementers, reviewers, and authors who need a precise contract.
- **Non-goals:** UI design, domain-specific event schemas, and step plugin authoring guides (documented elsewhere).

---

## 1. Goals

Workflows v2 is designed to be:

- **YAML-first**: YAML is the authoring source of truth.
- **Safe by construction**: no arbitrary code execution; expressions are restricted.
- **Deterministic**: given the same inputs and adapter behavior, execution is deterministic.
- **Auditable**: every executed step is persisted with inputs/outputs/errors.
- **Crash-resumable**: the system can recover from worker crashes using DB checkpointing.
- **UI-agnostic**: a Flow UI can be built later without changing the spec.

---

## 2. Core Concepts

### 2.1 Workflow Definition

A **definition** is a YAML document that compiles into an internal IR. The IR is the runtime input for execution and validation.

### 2.2 Event (read-only input)

An **event** is a JSON-like object (mapping/list/scalars) supplied by the trigger integration.

- Available to templates and expressions via `event.*`
- **Read-only**: workflows must not mutate the event
- **Schema is domain-defined**: the workflow spec does not define the contents of `event` (e.g. whether it contains `payload`, `device`, `request`, etc.)

Example references (structural, not domain-specific):
- `${event.payload.id}`
- `${event.meta.source}`

### 2.3 Vars (mutable state)

Each workflow **instance** has mutable variables stored under `vars`.

- Available via `vars.*`
- Mutated only by step types that write to vars (e.g. `set`, `compute`, `webhook.capture`)
- Persisted after every executed step (checkpointing)

### 2.4 Steps, Step IDs, and Flow

A workflow contains named steps under `workflow.steps`.

- The **YAML key** under `workflow.steps` is the **step ID**.
- Step IDs are stable identifiers used by:
  - routing (`flow.from`, `flow.to`)
  - persistence and audit logs (StepRun records)
  - UI labels (via optional `title`, but the ID remains the stable identifier)

### 2.5 Outcome and Routing

Some steps produce an **outcome** string. Outcomes are used only for routing via `flow`:

- `logic` produces an outcome by evaluating cases
- `approval` produces an outcome later via external decision

Outcome-based transitions must cover all possible outcomes.

### 2.6 Execution Modes (sync vs db)

This spec defines the workflow language and runtime semantics. An implementation may execute steps using different scheduling modes:

- **sync mode**: dispatch runs the instance immediately (still checkpointed per step).
- **db mode**: dispatch enqueues jobs; a worker claims jobs and runs steps.

Both modes MUST produce the same final instance state (modulo timestamps), assuming the same adapters and inputs.

---

## 3. Top-Level YAML Schema

### 3.1 Required fields

```yaml
schema: trustpoint.workflow.v2
name: <string>
enabled: <bool>

trigger:
  on: <string>
  sources: <sources mapping>

apply: <optional list of conditions>

workflow:
  start: <step_id>
  steps: <map step_id -> step>
  flow: <list of transitions>
```

### 3.2 Semantics

- `schema` MUST equal `trustpoint.workflow.v2`
- `name` MUST be a non-empty string
- `enabled` controls whether the definition is eligible for automatic triggering
- `trigger.on` identifies the event key used by the event registry
- `trigger.sources` narrows which emitters/scopes can trigger the workflow
- `apply` is an additional filter evaluated against the runtime context
- `workflow.start` is the first step ID
- `workflow.steps` defines step nodes
- `workflow.flow` defines routing edges

---

## 4. Trigger and Apply

### 4.1 trigger.on

`trigger.on` MUST be a known event key in the event registry.

### 4.2 trigger.sources

Sources define scoping rules for triggering. This spec defines the shape:

```yaml
trigger:
  on: example.event
  sources:
    trustpoint: <bool>
    ca_ids: <list[int]>
    domain_ids: <list[int]>
    device_ids: <list[string]>
```

Rules:

- If `trustpoint: true`, the workflow matches globally (subject to `apply`).
- If `trustpoint: false`, at least one of `ca_ids`, `domain_ids`, `device_ids` MUST be non-empty.

> Note: The meaning of CA/domain/device IDs is domain/integration-specific. The workflow language only defines the matching mechanism.

### 4.3 apply

`apply` is an optional list of **conditions** evaluated with AND semantics:

- If `apply` is omitted or empty: it matches.
- Otherwise: all conditions MUST evaluate to true for the workflow to start.

Conditions are defined in **Section 8** and reused by `logic` steps.

---

## 5. Workflow Graph

### 5.1 Steps map

`workflow.steps` MUST be a non-empty mapping:

```yaml
workflow:
  steps:
    step_a:         # <-- step_id
      type: set
      vars:
        foo: bar
```

### 5.2 Flow transitions

Each item in `workflow.flow` is either:

**Unconditional:**
```yaml
- from: step_a
  to: step_b
```

**Outcome-based:**
```yaml
- from: decide
  on: ok
  to: step_ok
```

### 5.3 Compiler-enforced invariants

The compiler MUST reject definitions that violate:

- `workflow.start` references a non-existent step ID
- `flow.from` or `flow.to` references a non-existent step ID
- a step has both unconditional and outcome transitions
- duplicate transitions exist for the same `(from, on)`
- non-terminal steps do not have exactly one unconditional transition unless they produce outcomes
- outcome-producing steps are missing mappings for any of their possible outcomes
- terminal steps have outgoing transitions

---

## 6. Step Model

### 6.1 Common fields

Every step MUST be a mapping with:

```yaml
type: <string>     # required
title: <string>    # optional (UI label only)
```

The step ID is the key in `workflow.steps`.

### 6.2 Built-in step types

This spec defines these built-in step types:

- `set`
- `compute`
- `logic`
- `email`
- `webhook`
- `approval`
- terminal: `stop`, `succeed`, `fail`, `reject`

Unknown step types MUST be rejected at compile time.

---

## 7. Templates and Expressions

### 7.1 Template interpolation: `${...}`

Many string fields MAY contain `${...}` expressions. A single string may contain multiple interpolations.

Example:
```yaml
subject: "Hello ${vars.user}, request ${event.payload.id}"
```

### 7.2 Expression language (restricted)

Inside `${...}`, only these forms are allowed:

- variable references: `event.<path>` or `vars.<path>`
- allowlisted function calls: `fn(arg1, arg2, ...)`

No assignments. No control flow. No arbitrary code.

> Allowlisted function names and exact behavior are part of the implementation contract and documented in the expressions reference (separate doc). The spec requires the set to be explicit and finite.

### 7.3 Missing paths

If a referenced path does not exist at runtime, it resolves to `null` (unless an implementation chooses to surface it as an execution error for a given usage site).

---

## 8. Conditions DSL (used by apply and logic)

Conditions evaluate to boolean and are:

- declarative
- side-effect free
- non-Turing complete
- safe to evaluate at runtime

### 8.1 Supported operators

A condition is a mapping with exactly one top-level operator:

- `exists`
- `not`
- `and`
- `or`
- `compare`

#### exists
```yaml
exists: ${vars.foo}
```

True iff the evaluated value is not null.

#### not
```yaml
not:
  exists: ${vars.foo}
```

#### and
```yaml
and:
  - exists: ${vars.foo}
  - compare:
      left: ${vars.count}
      op: ">="
      right: 10
```

#### or
```yaml
or:
  - compare:
      left: ${vars.status}
      op: "=="
      right: 200
  - compare:
      left: ${vars.status}
      op: "=="
      right: 201
```

#### compare
```yaml
compare:
  left: ${vars.count}
  op: "<="
  right: 10
```

Supported compare operators: `==`, `!=`, `<`, `<=`, `>`, `>=`.

### 8.2 Condition value operands

Operands MAY be:
- literals (string/number/bool/null)
- expression references via `${...}` (event/vars)
- templates that render to a value (implementation-defined)

### 8.3 Error handling

- Invalid condition structure MUST be a compile-time error.
- Runtime evaluation errors MUST be surfaced as step failure when encountered.

---

## 9. Step Type Specifications

### 9.1 set

Writes literal or templated values to vars.

Schema:
```yaml
type: set
vars:
  <key>: <value>
```

Semantics:
- Values are rendered (templates evaluated) before writing.
- Keys become entries under `vars`.

Example:
```yaml
set_defaults:
  type: set
  vars:
    reason: "foobar"
    count: 0
```

### 9.2 compute

Performs deterministic assignments to vars using safe operations.

Schema:
```yaml
type: compute
set:
  vars.<name>: <compute-expression>
```

**Two equivalent authoring forms are supported:**

A) Expression-string form (single `${...}`):
```yaml
compute_score:
  type: compute
  set:
    vars.score: ${add(vars.http_status, 1)}
```

B) YAML-op form (operator mapping):
```yaml
compute_score:
  type: compute
  set:
    vars.score:
      add:
        - ${vars.http_status}
        - 1
```

Semantics:
- Targets MUST be `vars.<name>` (no other namespaces).
- The RHS is compiled into expression IR and evaluated at runtime.
- The result is stored in `vars.<name>`.

Error handling:
- Invalid target paths are compile-time errors.
- Invalid operator names/arity are compile-time errors where detectable.
- Runtime type errors result in step failure.

### 9.3 logic

Evaluates cases in order and produces an outcome string.

Schema:
```yaml
type: logic
cases:
  - when: <condition>
    outcome: <string>
default: <string>
```

Semantics:
- First matching `when` wins and returns its `outcome`
- If no case matches, returns `default`

Flow requirement:
- Every possible produced outcome MUST have an outcome-based transition in `workflow.flow`.

Example:
```yaml
route:
  type: logic
  cases:
    - when:
        compare:
          left: ${vars.status}
          op: "=="
          right: 200
      outcome: ok
  default: fail
```

### 9.4 webhook

Calls an HTTP endpoint using the configured adapter.

Schema:
```yaml
type: webhook
method: GET | POST | PUT | PATCH | DELETE
url: <string>
headers: <map[string, string]>      # optional
body: <any>                         # optional (string/list/map/null)
timeout_seconds: <int>              # optional
capture:                            # optional
  status_code: vars.<name>
  body: vars.<name>
  headers: vars.<name>
```

Semantics:
- `url`, `headers`, and `body` support template rendering.
- `capture` writes selected response fields into vars targets.
- Non-2xx does not automatically fail; workflows should model handling explicitly via `logic`.

### 9.5 email

Sends an email using the configured adapter.

Schema:
```yaml
type: email
to: <list[string]>
cc: <list[string]>      # optional
bcc: <list[string]>     # optional
subject: <string>
body: <string>
```

Semantics:
- `subject` and `body` are template-rendered.
- Adapter delivery errors fail the step.

### 9.6 approval

Pauses execution until an external decision is recorded.

Schema:
```yaml
type: approval
approved_outcome: <string>
rejected_outcome: <string>
timeout_seconds: <int>   # optional (implementation-defined behavior)
```

Semantics:
- When reached, execution enters an awaiting state and does not continue automatically.
- The runtime persists an approval record tied to (instance, step_id).
- Later, an external system resolves the approval to either:
  - the configured `approved_outcome`, or
  - the configured `rejected_outcome`

Flow requirement:
- `workflow.flow` MUST include outcome-based transitions for both outcomes.

Example:
```yaml
manager_approval:
  type: approval
  approved_outcome: approved
  rejected_outcome: rejected
```

### 9.7 Terminal steps

Terminal types: `stop`, `succeed`, `fail`, `reject`

Rules:
- Terminal steps MUST NOT have outgoing transitions.
- They end the instance in a terminal status.

Schemas:

**stop**
```yaml
type: stop
reason: <string>
```

**succeed**
```yaml
type: succeed
message: <string>   # optional
```

**fail**
```yaml
type: fail
reason: <string>    # optional
```

**reject**
```yaml
type: reject
reason: <string>
```

---

## 10. Runtime State Model (Instances, Runs, Jobs)

This section defines the conceptual model required to interpret persistence and execution.

### 10.1 Instance

A workflow **instance** represents one execution of one definition for one triggering event.

Properties:
- `event_json`: the input event (read-only)
- `vars_json`: mutable vars
- `current_step`: step ID of the next step to execute (or None when terminal)
- `status`: execution lifecycle state

Checkpointing rule (normative):
- After each step execution, the runtime MUST persist:
  - the step run record (StepRun)
  - updated instance vars
  - updated instance status and current_step

### 10.2 Run

A **run** groups multiple instances created from a single trigger emission, when multiple workflow definitions match.

Run status is an aggregation of child instance statuses (implementation-defined ordering is allowed; must be deterministic).

### 10.3 Job

A **job** is a unit of scheduled execution for an instance. Jobs exist to support DB-driven workers.

- In db mode, dispatch enqueues an initial job per instance.
- The worker claims jobs, executes exactly one step, and:
  - marks the job done,
  - enqueues the next job if the instance is not terminal/awaiting/paused.

Jobs do not “bring the workflow to the end” by themselves:
- A job advances execution by one step.
- The sequence of jobs advances the instance until it reaches a terminal or awaiting state.

---

## 11. Concurrency and “Parallel Execution”

This spec distinguishes two forms of concurrency:

### 11.1 Parallel workflows (allowed)

A single event emission MAY create multiple instances (from multiple matching definitions). These instances are independent and MAY execute concurrently.

### 11.2 Parallel steps within an instance (not supported)

Within a single instance, execution is strictly step-by-step (no fork/join, no DAG parallelism). Only one current step exists at a time.

---

## 12. Full Example YAML (end-to-end)

This example demonstrates:
- trigger + sources
- apply filter
- webhook + capture
- logic routing by outcome
- compute in YAML-op form
- approval outcomes
- terminal stop paths

```yaml
schema: trustpoint.workflow.v2
name: Example — Review and Route
enabled: true

trigger:
  on: device.created
  sources:
    trustpoint: true
    ca_ids: []
    domain_ids: []
    device_ids: []

apply:
  - exists: ${event.device.serial_number}

workflow:
  start: call_endpoint

  steps:
    call_endpoint:
      type: webhook
      title: Call endpoint
      method: POST
      url: "https://example.com/api/items/${event.device.serial_number}"
      headers:
        x-request-id: "${event.meta.request_id}"
      body:
        serial_number: "${event.device.serial_number}"
      capture:
        status_code: vars.http_status
        body: vars.http_body

    route_status:
      type: logic
      title: Route by status code
      cases:
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 200
          outcome: ok
        - when:
            compare:
              left: ${vars.http_status}
              op: "=="
              right: 403
          outcome: needs_approval
      default: fail

    compute_score:
      type: compute
      title: Compute score
      set:
        vars.score:
          add:
            - ${vars.http_status}
            - 1

    approval_gate:
      type: approval
      title: Manual approval
      approved_outcome: approved
      rejected_outcome: rejected

    stop_ok:
      type: set
      vars: {}

    stop_fail:
      type: stop
      reason: "fail (status=${vars.http_status})"

    stop_rejected:
      type: stop
      reason: "rejected by approver"

  flow:
    - from: call_endpoint
      to: route_status

    - from: route_status
      on: ok
      to: compute_score

    - from: compute_score
      to: stop_ok

    - from: route_status
      on: needs_approval
      to: approval_gate

    - from: approval_gate
      on: approved
      to: stop_ok

    - from: approval_gate
      on: rejected
      to: stop_rejected

    - from: route_status
      on: fail
      to: stop_fail
```
---

## 13. Versioning and Compatibility

- `schema` identifies the language contract.
- The compiler produces an IR with a stable `ir_version`.
- Publishing MUST be blocked on compile errors.
- The system SHOULD store:
  - original YAML
  - compiled IR
  - source hash and IR hash for auditing

---

## 14. Out of Scope

- UI/Flow editor format
- Plugin step authoring contract
- Domain-specific event payload schemas
- Step-level retry/backoff policy (may be added later)
- Fork/join parallelism within an instance

---
