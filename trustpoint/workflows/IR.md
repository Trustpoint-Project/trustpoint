# Intermediate Representation (IR) — Workflows v2

This document defines the compiled Intermediate Representation (IR) format.
The IR is produced from YAML at publish time and is the only format executed by the runtime.

Goals:
- Make runtime execution simple and deterministic
- Catch all structural/spec errors at compile time
- Provide stable, auditable artifacts (hashable, versioned)
- Keep UI concerns out of runtime

---

## 1. Principles

1) YAML is authoring format; IR is execution format.
2) IR must be:
   - fully validated
   - normalized (defaults applied)
   - free of YAML-specific conveniences
3) IR must not contain UI state.
4) The compiler produces a stable IR hash for auditability.

---

## 2. IR top-level structure

```json
{
  "ir_version": "v2",
  "name": "Device onboarding",
  "enabled": true,

  "trigger": {
    "on": "device.created",
    "sources": {
      "trustpoint": true,
      "ca_ids": [],
      "domain_ids": [],
      "device_ids": []
    }
  },

  "apply": [ <predicate_ast>, ... ],

  "workflow": {
    "start": "notify",
    "steps": { "<step_id>": <step_ir>, ... },
    "transitions": {
      "<step_id>": <transition_ir>
    }
  },

  "meta": {
    "compiled_at": "<iso8601>",
    "compiler_version": "<string>",
    "source_hash": "<hash of YAML text>",
    "ir_hash": "<hash of normalized IR>"
  }
}
```

Notes:
- IR is JSON-compatible (stored as JSON in DB).
- The author never writes IR directly.

---

## 3. Step IR

Each step in `workflow.steps` compiles to:

```json
{
  "id": "notify",
  "type": "email",
  "title": "Send creation email",
  "params": { ... },
  "produces_outcome": false,
  "outcomes": []
}
```

### `params`
- Step type-specific fields
- Expressions in strings are compiled (see 3.1)

### `produces_outcome`
- `true` for step types that produce outcomes (e.g. `logic`, `approval`)
- `false` for linear steps

### `outcomes`
- All possible outcomes the step can emit, if applicable
- For `logic`: union of all `cases[].outcome` plus `default`
- For `approval`: `{approved_outcome, rejected_outcome}`

---

### 3.1 Compiled templates in IR (strings with `${...}`)

Any string that may contain `${...}` is compiled to a template IR:

```json
{
  "kind": "template",
  "parts": [
    {"kind": "text", "value": "Device "},
    {"kind": "expr", "expr": <expr_ast>},
    {"kind": "text", "value": " created"}
  ]
}
```

If a string contains no `${...}`, it may remain a plain string or still be represented as a template with one text part (compiler choice).

---

## 4. Expression AST (for `${...}`)

Expressions compile to a small AST.
Only two forms are allowed: reference and function call.

### 4.1 Reference
```json
{ "kind": "ref", "path": ["event", "device", "common_name"] }
```

### 4.2 Function call
```json
{
  "kind": "call",
  "name": "upper",
  "args": [
    { "kind": "ref", "path": ["event", "device", "common_name"] }
  ]
}
```

Compiler rules:
- function name must be allowlisted
- arity must match allowlisted signature(s)

---

## 5. Predicate AST (for conditions)

Conditions compile to predicate AST nodes.

### 5.1 exists
```json
{ "op": "exists", "arg": <value_ast> }
```

### 5.2 not
```json
{ "op": "not", "arg": <predicate_ast> }
```

### 5.3 and/or
```json
{ "op": "and", "args": [ <predicate_ast>, ... ] }
```

```json
{ "op": "or", "args": [ <predicate_ast>, ... ] }
```

### 5.4 compare
```json
{
  "op": "compare",
  "left": <value_ast>,
  "cmp": "==",
  "right": <value_ast>
}
```

Where `<value_ast>` is either:
- literal
- reference
- function call

---

## 6. Transition IR (flow)

Flow compiles into a normalized transition table per step:

### 6.1 Linear transition
```json
{
  "kind": "linear",
  "to": "call_status"
}
```

### 6.2 Outcome transitions
```json
{
  "kind": "by_outcome",
  "map": {
    "ok": "success_mail",
    "fail": "set_reason"
  }
}
```

Compiler rules:
- For non-outcome steps, transition must be linear or absent if terminal.
- For outcome-producing steps, transition must be `by_outcome` and contain mappings for all possible outcomes.

---

## 7. Step type-specific IR params

### 7.1 email
```json
{
  "to": ["..."],
  "cc": [],
  "bcc": [],
  "subject": <template_or_string>,
  "body": <template_or_string>
}
```

### 7.2 webhook
```json
{
  "method": "POST",
  "url": <template_or_string>,
  "headers": { "X": <template_or_string>, ... },
  "body": <template_or_json>,
  "timeout_seconds": 10,
  "capture": {
    "status_code": ["vars", "http_status"],
    "body": ["vars", "http_body"]
  }
}
```

Capture targets compile to a normalized path array.

### 7.3 logic
```json
{
  "cases": [
    { "when": <predicate_ast>, "outcome": "ok" },
    { "when": <predicate_ast>, "outcome": "fail" }
  ],
  "default": "fail"
}
```

### 7.4 compute
```json
{
  "set": {
    "vars.total": <compute_expr_ast>,
    "vars.average": <compute_expr_ast>
  }
}
```

Where `compute_expr_ast` is a restricted tree of operations (add/mul/etc.) with operands that are value ASTs.

### 7.5 stop
```json
{ "reason": <template_or_string> }
```

### 7.6 approval
```json
{
  "approved_outcome": "approved",
  "rejected_outcome": "rejected"
}
```

---

## 8. Compiler outputs and auditability

On publish:
- store YAML source text
- compile and store IR JSON
- compute and store:
  - `source_hash` (hash of YAML text)
  - `ir_hash` (hash of canonicalized IR JSON)

Canonicalization:
- deterministic key ordering
- normalized defaults included
- no timestamps inside canonical IR for hashing (meta is excluded or handled separately)

---

## 9. Runtime expectations (what IR guarantees)

The runtime may assume:
- All step IDs exist and are unique
- All transitions are valid and complete
- All expressions and predicates are valid and safe
- All outcomes are mapped
- Terminal steps have no outgoing transitions

Therefore runtime can be implemented as a simple state machine over:
- current step id
- vars
- event
- step run history
