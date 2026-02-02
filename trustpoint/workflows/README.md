# TrustPoint Workflows v2 (YAML-first)

This document describes the v2 workflow system for TrustPoint.

Goals:
- YAML-first authoring (no JSON-in-YAML required)
- Safe, deterministic execution (no arbitrary code execution)
- Auditable runs (step-by-step history, inputs/outputs/errors)
- Extensible step types (plugin model)
- UI-agnostic (Flow UI can be built later on top of the same spec)

## Core Concepts

### Event
A workflow is triggered by an `event`. The runtime provides an `event` object (read-only) to steps and expressions.

Examples:
- `event.device.common_name`
- `event.request.id`

### Vars
A workflow run has mutable variables under `vars`. Steps may write to `vars` via `capture` (e.g. webhook outputs) or via `compute`.

Examples:
- `vars.http_status`
- `vars.total_score`

### Steps
A workflow consists of named steps. Step IDs are chosen by the author:

```yaml
steps:
  notify_owner:
    type: email
    title: Send notification email
    ...
```

Each step has:
- `type` (e.g. `email`, `webhook`, `logic`, `compute`, `stop`, `approval`)
- optional `title` (UI label; the ID remains stable)

### Flow
`flow` describes unconditional transitions and outcome-based transitions.

- Unconditional transition:
```yaml
- from: step_a
  to: step_b
```

- Outcome-based transition (used after `logic` steps):
```yaml
- from: choose_path
  on: ok
  to: next_step
```

### Logic step outcomes
A `logic` step evaluates `cases` and produces an `outcome` string.
The `flow` section maps each possible outcome to the next step.

### Expressions in strings: `${...}`
String fields may contain `${...}` interpolations.

Examples:
- `${event.device.common_name}`
- `${upper(event.device.common_name)}`
- `${default(vars.http_status, 0)}`

The expression language is restricted:
- variable references (`event.*`, `vars.*`)
- allowlisted formatting functions

No loops, no assignments, no arbitrary code.

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
        - test.test@gmx.de
      subject: New device: ${event.device.common_name}
      body: |
        Device was created.
        ID: ${event.device.id}

    stop:
      type: stop
      reason: Done

  flow:
    - from: notify
      to: stop
```

## Notes on v2 philosophy
- Authoring YAML is the source of truth.
- On publish, YAML is validated and compiled to an internal IR used by the runtime.
- Flow UI is not required for v2; it can be added later.
```
</pre>

<pre>
# workflows_v2/SPEC.md

```markdown
# Workflows v2 Specification

This document defines the YAML contract for TrustPoint workflow definitions.

## 1. Top-level fields

```yaml
schema: trustpoint.workflow.v2        # required
name: <string>                        # required
enabled: <bool>                       # required

trigger:                              # required
  on: <string>                        # required (e.g. device.created)
  sources:                            # optional but recommended
    trustpoint: <bool>                # optional (default false)
    ca_ids: <list[int]>               # optional (default [])
    domain_ids: <list[int]>           # optional (default [])
    device_ids: <list[string]>        # optional (default [])

apply:                                # optional list of conditions (AND semantics)
  - <condition>
  - <condition>

workflow:                             # required
  start: <step_id>                    # required
  steps: <map step_id -> step>        # required
  flow: <list of transitions>         # required
```

### Semantics
- `enabled: false` means the workflow will not be triggered automatically.
- `trigger.on` selects an event type.
- `trigger.sources` narrows which emitters/scopes can trigger the workflow.
  - If `trustpoint: true`, workflow can trigger globally (subject to `apply` conditions).
  - If `trustpoint: false`, at least one of `ca_ids`, `domain_ids`, `device_ids` should be non-empty.
- `apply` is an additional filter evaluated against the runtime `event` and initial `vars`.
  - All `apply` conditions must match (logical AND).

## 2. Step IDs
Step IDs are the keys under `workflow.steps`. They must:
- be unique
- be stable identifiers (recommended: lowercase with underscores)

Example:
```yaml
steps:
  call_status:
    type: webhook
```

## 3. Step structure

A step is a YAML mapping with at least:

```yaml
type: <string>        # required
title: <string>       # optional
```

Step type schemas are defined in STEPS.md. Unknown `type` is a compile error.

## 4. Flow transitions

A transition is either unconditional or outcome-based.

### Unconditional transition
```yaml
- from: <step_id>
  to: <step_id>
```

### Outcome-based transition (used with `logic` step outcomes)
```yaml
- from: <logic_step_id>
  on: <outcome_string>
  to: <step_id>
```

### Flow invariants (compiler enforced)
- Every `from` step referenced in `flow` must exist in `steps`.
- Every `to` step referenced in `flow` must exist in `steps`.
- Duplicate transitions with the same `(from, on)` are a compile error.
- For unconditional transitions, `(from)` may appear at most once as unconditional.
- For outcome-based transitions, a `logic` step may have multiple `on:` entries.

### Terminal steps
Some step types are terminal (e.g. `stop`). Terminal steps must not have outgoing transitions.
If a terminal step has any outgoing transition, it is a compile error.

## 5. Logic step (outcome selection)

A `logic` step evaluates cases and returns an outcome string.

```yaml
type: logic
cases:
  - when: <condition>
    outcome: <string>
  - when: <condition>
    outcome: <string>
default: <string>
```

### Logic invariants (compiler enforced)
- `cases` must be a non-empty list.
- `default` must be present.
- Each case must contain `when` and `outcome`.
- All outcomes that can be produced by the logic step (case outcomes + default) must have a corresponding flow transition:
  - `- from: <logic_step_id> on: <outcome> to: ...`
- If any possible outcome has no transition mapping, it is a compile error.

## 6. Conditions

Conditions are a restricted, declarative DSL (non-Turing complete).
Full definition lives in CONDITIONS.md.

Supported forms:
- `exists`
- `not`
- `and`
- `or`
- `compare`

### compare
```yaml
compare:
  left: <value>
  op: "==" | "!=" | "<" | "<=" | ">" | ">="
  right: <value>
```

Values may be:
- literals (string/number/bool/null)
- references `${event.*}` or `${vars.*}`

## 7. String interpolation and formatting functions

Strings may contain `${...}` interpolations.
Expressions support:
- variable references: `event.*`, `vars.*`
- allowlisted function calls (see EXPRESSIONS.md)

No arbitrary code execution.

## 8. Compute step (variable updates)

A `compute` step writes to `vars` using safe arithmetic operations.
Full definition lives in STEPS.md.

Example:
```yaml
type: compute
set:
  vars.total:
    add:
      - ${vars.a}
      - ${vars.b}
      - 10
```

## 9. Versioning and compilation
- YAML is the authoring source of truth.
- On publish, YAML is validated and compiled to a runtime IR.
- Compiler errors block publishing.
- The system stores:
  - original YAML
  - compiled IR
  - hash of IR for auditability
