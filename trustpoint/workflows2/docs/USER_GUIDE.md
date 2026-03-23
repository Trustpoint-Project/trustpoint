# Workflows 2 User Guide

## What Workflows 2 Is

Workflows 2 is a YAML-first automation system.

You author a workflow definition in YAML, and the editor gives you three coordinated helpers around it:

- a YAML editor for direct authoring
- a draft graph editor for structural editing and visualization
- a context-aware guide drawer for inserting documented DSL pieces

YAML stays the source of truth. The graph and guide never replace it.

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

### `set`

Writes literal or templated values into workflow vars.

```yaml
mark_ok:
  type: set
  vars:
    result: ok
    message: Status was ${vars.http_status}
```

Important:

- `set.vars` uses plain variable names like `result`, not `vars.result`.

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
  approved_outcome: approved
  rejected_outcome: rejected
  timeout_seconds: 3600
```

Notes:

- Approval steps are outcome-producing.
- Both approval outcomes must be routed in `workflow.flow`.

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

Special targets:

- `$end`
- `$reject`

Example:

```yaml
- from: route_status
  on: fail
  to: $reject
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

- insert documented snippets
- inspect field requirements
- edit structured content for logic, webhook, compute, and set steps
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
