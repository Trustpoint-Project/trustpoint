# TrustPoint Workflows v2 — Specification (YAML-first)

This document is the **normative** specification for TrustPoint Workflows v2.
It defines the YAML contract, runtime execution semantics, and state machines.

Goals:
- YAML-first authoring (no JSON-in-YAML required)
- Safe, deterministic execution (no arbitrary code)
- Crash-resumable execution (DB checkpointing, step-by-step jobs)
- Auditable history (immutable step run records)
- UI-agnostic (a flow UI can be built later on top of this spec)

Non-goals:
- A general-purpose programming language
- Async orchestration frameworks / distributed queues (v2 ships DB worker only)
- Step-level retry semantics beyond worker/job retries (may be added later)

---

## 1. Glossary & Core Concepts

### 1.1 Event
A workflow is triggered by an **event**. At runtime, steps and expressions can read a read-only `event` object.

Examples:
- `${event.device.common_name}`
- `${event.request.id}`

### 1.2 Vars
A workflow instance has mutable variables under `vars`. Steps may write to `vars` via:
- `set` step (templated assignment)
- `compute` step (expression assignment)
- `webhook.capture` (copy response data into `vars`)

Examples:
- `${vars.http_status}`
- `${vars.total_score}`

### 1.3 Workflow Definition
A workflow definition is authored in YAML and compiled into an internal deterministic IR.
Stored:
- YAML text
- compiled IR JSON
- `ir_hash` (sha256) for auditability and caching

### 1.4 Run
A **Run** represents one trigger emission that may spawn **N instances** (one per matching definition).
A Run is the natural unit for grouping, UI display, and future EST gating.

Properties:
- `trigger_on` (event key)
- `event_json` (payload)
- `source_json` (scope details)
- optional `idempotency_key` (dedupe / polling use-cases)

### 1.5 Instance
An **Instance** represents one execution of one workflow definition.
Instances are the semantic execution units that users care about.

Instances store:
- `event_json`
- `vars_json`
- `current_step` (the next step to execute; see invariants)
- `status` (semantic lifecycle)

### 1.6 Job
A **Job** is the mechanical scheduling unit for DB-run mode.

Hard rule:
- **Exactly one step per job**

Jobs exist to achieve:
- crash-resumable execution
- leasing (avoid duplicate processing)
- backoff retries (job-level)

Job status is *mechanical*, not semantic; it does not represent the workflow’s business outcome.

### 1.7 StepRun
A **StepRun** is an immutable audit record of one executed step, including:
- inputs (implicit via event/vars snapshot semantics)
- outputs
- vars delta
- errors
- timestamps
- chosen outcome and next step

### 1.8 Approval
An **Approval** is a persisted request created by an `approval` step.
It pauses the instance until an external decision is recorded.

---

## 2. Execution Model (Normative)

### 2.1 Determinism
Given the same:
- definition IR
- event
- initial vars
- external adapter responses (email/webhook, etc.)

the engine must produce the same:
- sequence of StepRuns
- vars mutations
- terminal state

### 2.2 Executor vs RuntimeService
Two layers exist:

- **Executor (pure engine)**
  - Executes exactly one step given IR + context
  - Returns a `StepRun` result
  - Must not mutate the database
  - Must not block on approvals

- **RuntimeService (DB checkpointing)**
  - Owns instance lifecycle and persistence
  - Writes StepRun rows
  - Updates instance `vars_json`, `status`, and `current_step`
  - Creates and resolves Approval rows
  - Recomputes Run status

### 2.3 Crash-resumable job model
In DB mode:
- Each Job executes **exactly one step** of an Instance.
- After executing a step, the RuntimeService **must persist**:
  - StepRun
  - updated vars
  - updated current_step
  - updated instance status

If the instance is not terminal and not awaiting, the worker enqueues the next Job.

### 2.4 Invariants
The system must maintain the following invariants:

1) **One-step checkpoint**
- After a step is executed, its effects are persisted before proceeding.

2) **current_step points to next executable step**
- `Instance.current_step` always points to the **next step to execute**.
- Terminal instances have `current_step = null`.
- Awaiting instances keep `current_step = <approval_step_id>`.

3) **No implicit progress**
- Instances in `PAUSED` or `AWAITING` must not auto-advance without explicit action.

4) **No blocking approvals in executor**
- The `approval` step never waits inside the executor.
- It always produces status `awaiting`.

---

## 3. State Machines

This section defines the **normative state machines**.
State names match Django model constants.

### 3.1 Instance status (semantic)

#### Non-terminal
- `queued` — created/enqueued but not yet executing
- `running` — actively executing steps
- `awaiting` — waiting for an approval decision
- `paused` — execution halted due to crash/lease expiry; manual resume required

#### Terminal
- `succeeded` — reached a `succeed` step
- `stopped` — reached a `stop` step
- `rejected` — reached a `reject` step
- `failed` — reached a `fail` step or a fatal runtime error
- `cancelled` — explicitly cancelled by an operator/system policy

#### Allowed transitions (high-level)

- `queued → running` (worker claims a job / sync run starts)
- `running → awaiting` (approval step executed)
- `awaiting → running` (approval resolved)
- `running → paused` (worker crash detected via lease expiry)
- `running → terminal` (stop/succeed/reject/fail)
- `queued → terminal` (rare; e.g. cancelled before start)
- `paused → queued` (manual resume action)

### 3.2 Job status (mechanical)

Jobs are not semantic states and do not map 1:1 to instance states.

- `queued` — scheduled and waiting to be claimed
- `running` — claimed by a worker (lease in effect)
- `done` — completed successfully (one step executed and persisted)
- `failed` — step execution failed or lease expired during processing
- `cancelled` — operator/system explicitly cancelled the job

Normative notes:
- A job may be `failed` while the instance is `paused`.
- A job may be `done` while the instance becomes `awaiting` (approval step executed successfully).

### 3.3 Run status aggregation
A Run aggregates the statuses of its child instances.

Priority order (highest first):
`rejected > failed > stopped > paused > awaiting > running > queued > succeeded`

Rules:
- If any instance is `rejected`, run is `rejected`.
- Else if any instance is `failed`, run is `failed`.
- Else if any instance is `stopped`, run is `stopped`.
- Else if any instance is `paused`, run is `paused`.
- Else if any instance is `awaiting`, run is `awaiting`.
- Else if any instance is `running`, run is `running`.
- Else if any instance is `queued`, run is `queued`.
- Else run is `succeeded`.

---

## 4. YAML Definition (Normative)

### 4.1 Top-level fields

```yaml
schema: trustpoint.workflow.v2        # required
name: <string>                        # required
enabled: <bool>                       # optional (default true)

trigger:                              # required
  on: <string>                        # required (e.g. device.created)
  sources:                            # optional (default: trustpoint: false; lists empty)
    trustpoint: <bool>
    ca_ids: <list[int]>
    domain_ids: <list[int]>
    device_ids: <list[string]>

apply:                                # optional list of conditions (AND semantics)
  - <condition>
  - <condition>

workflow:                             # required
  start: <step_id>                    # required
  steps: <map step_id -> step>        # required (non-empty)
  flow: <list of transitions>         # required (may be [] only for single-step workflows)
```

### 4.2 Trigger semantics
- `enabled: false` means the definition will not be selected by automatic dispatch.
- `trigger.on` selects the event type.
- `trigger.sources` narrows which emitters/scopes can trigger the workflow.
  - If `trustpoint: true`, the workflow can trigger globally (subject to `apply`).
  - If `trustpoint: false`, at least one of `ca_ids/domain_ids/device_ids` must be non-empty.

### 4.3 apply semantics
- `apply` is an additional filter evaluated against `event` and initial `vars`.
- All `apply` conditions must be true (logical AND).

---

## 5. Steps & Flow (Normative)

### 5.1 Step IDs
Step IDs are the keys under `workflow.steps`.
They must:
- be unique within the workflow
- be non-empty strings
- be stable identifiers (recommended: lowercase with underscores)

### 5.2 Common step fields
All steps support:

```yaml
type: <string>        # required
title: <string>       # optional, UI-only
```

### 5.3 Flow transitions

Unconditional transition:
```yaml
- from: <step_id>
  to: <step_id>
```

Outcome-based transition:
```yaml
- from: <step_id>
  on: <outcome_string>
  to: <step_id>
```

Compiler invariants:
- every referenced `from` and `to` must exist
- duplicate transitions for the same `(from)` (linear) are errors
- duplicate transitions for the same `(from, on)` are errors
- terminal steps must not have outgoing transitions
- outcome-producing steps must have mappings for all outcomes

---

## 6. Approval Semantics (Normative)

### 6.1 Runtime behavior
When an `approval` step is executed:
- Executor returns a StepRun with `status = "awaiting"`
- RuntimeService:
  - creates (or ensures) a Workflow2Approval row for `(instance, step_id)`
  - sets instance status to `awaiting`
  - keeps instance.current_step = approval step id
  - does **not** enqueue further jobs

### 6.2 Resolving approvals
External code resolves approval by writing a decision:
- decision must be `approved` or `rejected`
- RuntimeService:
  - updates approval status accordingly
  - sets instance status to `running`
  - sets instance.current_step to the next step from `flow` outcome mapping
  - the worker will then execute the next job

### 6.3 Approval timeouts
If `timeout_seconds` is defined:
- `expires_at` is persisted as created_at + timeout_seconds
- Expiry handling policy MUST be explicit (future extension):
  - either auto-reject, auto-fail, or leave pending and require operator action

v2 default (current):
- expiry is represented in the approval row; no automatic resolution unless implemented by a separate sweeper.

---

## 7. Conditions & Expressions

This spec delegates detailed syntax to:
- `docs/conditions.md`
- `docs/expressions.md`

Normative constraint:
- Conditions and expressions are non-Turing complete, side-effect free, deterministic.

---

## 8. Built-in Step Types

This spec delegates step schemas to:
- `docs/steps.md`

Normative constraint:
- Unknown step types are compile errors.
- Step params are validated at compile time.
- Runtime must never accept an invalid compiled step.

---

## 9. Compatibility & Versioning

- `schema` must equal `trustpoint.workflow.v2`.
- Any incompatible change requires a new schema key (e.g. `trustpoint.workflow.v3`).
- The compiler produces `ir_version: "v2"`.

---

## 10. Conformance

An implementation is v2-conformant if it:
- enforces compile-time validation for YAML schema
- preserves invariants in Section 2.4
- follows state machines in Section 3
- follows approval semantics in Section 6
- produces deterministic IR hashes for equivalent YAML

