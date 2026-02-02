# Built-in Step Types (Workflows v2)

This document defines the built-in step types supported by the workflow engine.
Each step type has:
- a declarative YAML schema
- well-defined runtime behavior
- clear compiler validation rules

---

## 1. Common step fields

All steps support the following common fields:

```yaml
type: <string>        # required
title: <string>       # optional, UI label only
```

The step ID (YAML key) is the stable identifier used by `flow`.

---

## 2. `email` step

Sends an email.

### Schema
```yaml
type: email
to: <list[string]>            # required
cc: <list[string]>            # optional
bcc: <list[string]>           # optional
subject: <string>             # required
body: <string>                # required
```

### Notes
- All string fields support `${...}` expressions.
- Rendering errors (invalid expressions) fail the step.
- Email delivery errors mark the step as failed.

### Example
```yaml
notify:
  type: email
  title: Notify owner
  to:
    - admin@example.com
  subject: Device ${event.device.common_name} created
  body: |
    Device ID: ${event.device.id}
```

---

## 3. `webhook` step

Calls an external HTTP endpoint.

### Schema
```yaml
type: webhook
method: GET | POST | PUT | PATCH | DELETE
url: <string>                          # required
headers: <map[string, string]>        # optional
body: <string | map>                  # optional
timeout_seconds: <int>                # optional (default engine-defined)

capture:                              # optional
  status_code: vars.<path>
  body: vars.<path>
  headers: vars.<path>
```

### Notes
- `url`, headers, and body support `${...}` expressions.
- `capture` writes response data into `vars`.
- Only explicitly captured fields are stored.
- Non-2xx responses do NOT automatically fail the step;
  failure handling should be modeled explicitly via `logic`.

### Example
```yaml
call_status:
  type: webhook
  method: POST
  url: https://example.com/status
  capture:
    status_code: vars.http_status
    body: vars.http_body
```

---

## 4. `logic` step

Evaluates conditions and produces an outcome.

### Schema
```yaml
type: logic
cases:
  - when: <condition>
    outcome: <string>
  - when: <condition>
    outcome: <string>

default: <string>
```

### Runtime behavior
- Conditions are evaluated in order.
- First matching case determines the outcome.
- If no case matches, `default` is used.

### Compiler rules
- `cases` must be non-empty.
- `default` must be present.
- All possible outcomes must be handled by `flow`.
- Outcomes must be strings (case-sensitive).

### Example
```yaml
route_status:
  type: logic
  title: Route by HTTP status
  cases:
    - when:
        compare:
          left: ${vars.http_status}
          op: "=="
          right: 200
      outcome: ok
  default: error
```

---

## 5. `compute` step

Performs deterministic variable assignments using safe operations.

### Schema
```yaml
type: compute
set:
  vars.<path>: <expression>
  vars.<path>: <expression>
```

### Supported operations

#### Arithmetic
```yaml
add: [a, b, ...]
sub: [a, b]
mul: [a, b, ...]
div: [a, b]
mod: [a, b]
```

#### Aggregation / helpers
```yaml
min: [a, b, ...]
max: [a, b, ...]
round: [a]
```

#### Casting
```yaml
to_int: <value>
to_str: <value>
```

Operands may be literals or `${...}` expressions.

### Example
```yaml
compute_score:
  type: compute
  set:
    vars.total:
      add:
        - ${vars.score_a}
        - ${vars.score_b}
        - 10

    vars.average:
      div:
        - ${vars.total}
        - 3
```

### Compiler rules
- Target paths must start with `vars.`
- Operations must have valid arity.
- Invalid operations are compile-time errors.

---

## 6. `set` step (simple assignment)

For simple, non-computed assignments.

### Schema
```yaml
type: set
vars:
  <key>: <value>
```

### Example
```yaml
set_reason:
  type: set
  vars:
    reason: "manual override"
```

Note: Prefer `compute` for arithmetic or derived values.

---

## 7. `approval` step

Pauses workflow execution until an external signal is received.

### Schema
```yaml
type: approval
approved_outcome: <string>      # required
rejected_outcome: <string>      # required
```

### Runtime behavior
- Workflow enters an AWAITING state.
- External system signals approve/reject.
- Step emits corresponding outcome.

### Flow example
```yaml
flow:
  - from: approval_step
    on: approved
    to: continue_step
  - from: approval_step
    on: rejected
    to: stop_fail
```

---

## 8. `stop` step

Terminates workflow execution.

### Schema
```yaml
type: stop
reason: <string>
```

### Notes
- `stop` is terminal.
- Must not have outgoing flow transitions.
- Reason is stored in execution history.

### Example
```yaml
stop_ok:
  type: stop
  reason: Everything worked
```

---

## 9. Error handling and retries (future extension)

v2 does not define retries at the step level.
This may be added in a future version via:

```yaml
retry:
  max_attempts: 3
  backoff_seconds: 10
```

---

## 10. Extensibility

Custom step types may be added via plugins.
Each plugin must define:
- schema
- compiler validation
- runtime executor
