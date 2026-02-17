# docs/conditions.md

```markdown
# Conditions DSL (Workflows v2)

This document defines the condition language used in:
- `apply`
- `logic` step cases

The condition language is:
- declarative
- non-Turing complete
- side-effect free
- safe to evaluate at runtime

Conditions always evaluate to a boolean.

---

## 1. General rules

- Conditions are YAML mappings.
- Exactly one operator must be present at the top level.
- Conditions may be nested.
- No condition may mutate `vars` or `event`.
- Any invalid condition results in a **compile-time error**.

---

## 2. Supported condition forms

### 2.1 `exists`

Checks whether a value is present and not null.

```yaml
exists: ${event.device.domain_id}
```

Semantics:
- `true` if the resolved value is not `null` and not `undefined`
- `false` otherwise

---

### 2.2 `not`

Negates a condition.

```yaml
not:
  exists: ${vars.http_status}
```

---

### 2.3 `and`

Logical AND over a list of conditions.

```yaml
and:
  - exists: ${vars.http_status}
  - compare:
      left: ${vars.http_status}
      op: "=="
      right: 200
```

Rules:
- List must contain at least one condition.
- All conditions must evaluate to `true`.

---

### 2.4 `or`

Logical OR over a list of conditions.

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

Rules:
- List must contain at least one condition.
- At least one condition must evaluate to `true`.

---

### 2.5 `compare`

Compares two values.

```yaml
compare:
  left: ${vars.count}
  op: "<="
  right: 10
```

#### Supported operators
- `"=="`  equal
- `"!="`  not equal
- `"<"`   less than
- `"<="`  less than or equal
- `">"`   greater than
- `">="`  greater than or equal

#### Value types
Operands may be:
- string
- number
- boolean
- null
- reference (`${event.*}`, `${vars.*}`)

#### Type rules
- Both sides must resolve to compatible types.
- Number ↔ number comparisons are allowed.
- String ↔ string comparisons are allowed.
- Mixed types result in a compile-time error
  (unless explicitly converted using formatting functions).

---

## 3. Evaluation context

Conditions may reference:
- `event.*` (read-only)
- `vars.*` (read-only for conditions)

Example:
```yaml
compare:
  left: ${event.device.common_name}
  op: "!="
  right: ""
```

---

## 4. Error handling

The compiler must raise an error if:
- an unknown operator is used
- a required field is missing
- a comparison uses incompatible types
- a reference path cannot be resolved

Runtime must never fail due to malformed conditions; all issues must be caught at compile time.

---

## 5. Design notes

- No implicit truthiness (e.g. empty string is not false).
- No arithmetic in conditions (use `compute` step instead).
- Conditions are intended for routing and filtering only.
