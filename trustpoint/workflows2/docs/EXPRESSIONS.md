# docs/expressions.md

```markdown
# Expressions and String Interpolation (Workflows v2)

This document defines the `${...}` expression syntax used in string fields.

Expressions are used in:
- email subject/body
- webhook URLs, headers, payloads
- condition operands
- compute step inputs

---

## 1. `${...}` interpolation

Strings may contain one or more `${...}` expressions.

Example:
```yaml
subject: Device ${event.device.common_name} created
```

Each `${...}` expression is evaluated independently and replaced with its string representation.

---

## 2. Expression grammar (restricted)

Inside `${...}` only the following forms are allowed:

1) Variable reference  
2) Function call with arguments

No assignments, no control flow, no arbitrary code execution.

---

## 3. Variable references

### Syntax
```text
event.<path>
vars.<path>
```

Examples:
- `${event.device.common_name}`
- `${vars.http_status}`

Rules:
- Missing paths at runtime resolve to `null`.

---

## 4. Formatting and helper functions

Functions are explicitly allowlisted.

### 4.1 String functions
- `upper(x)`
- `lower(x)`
- `title(x)`
- `truncate(text, length)`
- `replace(text, old, new)`
- `concat(a, b, c, ...)`

### 4.2 Defaulting and null-handling
- `default(x, fallback)`
- `coalesce(a, b, c, ...)`

### 4.3 Casting
- `str(x)`
- `int(x)`

### 4.4 Utility
- `len(x)`
- `json(x)`   (safe serialization for debugging/logging)

Examples:
```yaml
body: |
  Status: ${default(vars.http_status, "unknown")}
  Payload: ${json(event)}
```

---

## 5. Type behavior

- Functions define their own input requirements.
- Invalid argument types result in compile-time errors when detectable.
- Runtime type errors must be surfaced clearly and fail the step.

---

## 6. Security model

- No access to filesystem, environment, or system calls.
- No loops or recursion.
- No mutation of `vars` or `event` via expressions.
- Expressions are pure and deterministic.

---

## 7. Relationship to compute step

Expressions are for **reading and formatting** values.

All arithmetic, aggregation, and mutation must be done using the `compute` step.

Example (invalid):
```yaml
vars.total: ${vars.a + 5}   # NOT allowed
```