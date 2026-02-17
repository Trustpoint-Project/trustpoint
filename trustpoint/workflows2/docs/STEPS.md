# docs/steps.md

```markdown
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

---

## 3. `webhook` step

Calls an external HTTP endpoint.

### Schema
```yaml
type: webhook
method: GET | POST | PUT | PATCH | DELETE
url: <string>                          # required
headers: <map[string, string]>        # optional
body: <string | map | list | null>    # optional
timeout_seconds: <int>                # optional (default engine-defined)

capture:                              # optional
  status_code: vars.<name>
  body: vars.<name>
  headers: vars.<name>
```

### Notes
- `url`, headers, and body support `${...}` expressions.
- `capture` writes response data into `vars` (top-level var name).
- Non-2xx responses do NOT automatically fail the step; handle via `logic`.

---

## 4. `logic` step

Evaluates conditions and produces an outcome.

### Schema
```yaml
type: logic
cases:
  - when: <condition>
    outcome: <string>
default: <string>
```

Runtime behavior:
- Conditions are evaluated in order.
- First matching case determines the outcome.
- If no case matches, `default` is used.

Compiler rules:
- `cases` must be non-empty.
- `default` must be present.
- All outcomes must be mapped in `flow`.

---

## 5. `compute` step (v2 engine format)

Performs deterministic variable assignments using safe expressions.

### Schema
```yaml
type: compute
set:
  vars.<name>: ${expr(...)}   # required; must be a single expression string
```

Notes:
- Targets must be `vars.<name>` (one segment after vars).
- Values must be a single expression string `${...}` (no mixed text).

Example:
```yaml
type: compute
set:
  vars.total: ${add(vars.a, vars.b, 10)}
  vars.ratio: ${div(vars.total, 3)}
```

---

## 6. `set` step

Assigns templated values into `vars`.

### Schema
```yaml
type: set
vars:
  <key>: <value>   # values may contain templates/expressions
```

---

## 7. `approval` step

Pauses workflow execution until an external signal is received.

### Schema
```yaml
type: approval
approved_outcome: <string>      # required
rejected_outcome: <string>      # required
timeout_seconds: <int>          # optional
```

Runtime behavior (normative; see spec):
- Executor returns status `awaiting`
- RuntimeService persists an approval row
- Instance enters `awaiting`

---

## 8. `reject` step

Terminates the workflow as rejected.

### Schema
```yaml
type: reject
reason: <string>
```

---

## 9. `stop` step

Terminates the workflow as stopped.

### Schema
```yaml
type: stop
reason: <string>
```

---

## 10. `succeed` step

Terminates the workflow as succeeded.

### Schema
```yaml
type: succeed
message: <string>   # optional
```

---

## 11. `fail` step

Terminates the workflow as failed.

### Schema
```yaml
type: fail
reason: <string> | null   # optional
```
