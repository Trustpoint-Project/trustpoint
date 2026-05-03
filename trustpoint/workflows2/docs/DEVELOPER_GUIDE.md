# Workflows 2 Developer Guide

## Purpose

`workflows2` is a YAML-first workflow system with three major responsibilities:

1. Author workflow definitions in Django and the browser.
2. Compile YAML into a deterministic internal IR.
3. Execute compiled workflows with durable runtime state, approvals, and dedicated worker processes.

The most important architectural rule is simple:

- YAML is the authoring source of truth.

The editor, graph, and guide are all helpers around that YAML. They must not become a second canonical workflow model.

## High-Level Lifecycle

### Authoring

1. `trustpoint/templates/workflows2/definition_editor.html` renders the editor page.
2. `trustpoint/static/js/workflows2/editor_bundle.js` bootstraps the frontend.
3. The frontend edits YAML directly and derives semantic context, issues, and a draft graph from that YAML.
4. On save, Django posts the YAML back through `WorkflowDefinitionService`.
5. The service formats YAML canonically, compiles it, and stores both YAML and IR on `Workflow2Definition`.

### Compilation

1. YAML is loaded and linted.
2. Expressions, templates, conditions, steps, and flow are compiled into IR.
3. The compiler validates trigger compatibility, flow completeness, reachability, and variable availability.
4. The compiler emits metadata including source and IR hashes.

### Execution

1. An external event is emitted into `WorkflowDispatchService`.
2. Matching definitions create a `Workflow2Run`, one or more `Workflow2Instance` rows, and worker jobs.
3. A database-backed worker claims jobs and advances one step at a time.
4. `WorkflowRuntimeService` persists step runs and updates instance status.
5. `WorkflowExecutor` runs deterministic step logic against runtime `event` and `vars`.

## Backend Module Map

### Core models

`trustpoint/workflows2/models.py`

- `Workflow2Definition`: persisted YAML + compiled IR
- `Workflow2Run`: one emitted event / grouping record
- `Workflow2Instance`: execution of one definition
- `Workflow2StepRun`: immutable step audit record
- `Workflow2Approval`: persisted approval request
- `Workflow2Job`: job row for worker-backed execution
- `Workflow2WorkerHeartbeat`: worker presence / liveness

Important distinction:

- run status is bundle-level
- instance status is business execution state
- job status is worker-job lifecycle state

### Compiler

`trustpoint/workflows2/compiler/compiler.py`

- orchestration entry point
- step param compilation
- flow compilation
- flow completeness validation
- reachability validation
- variable availability validation

Supporting modules:

- `lint.py`: lightweight schema/key guardrails
- `expr.py`: expression parser and allowlist
- `templates.py`: `${...}` template compilation into IR
- `conditions.py`: condition DSL compilation
- `yaml_loader.py`: YAML loading
- `yaml_format.py`: canonical YAML formatting before save
- `hashing.py`: stable source/IR hashes

### Catalog and events

Catalog metadata powers the editor UI.

- `catalog/steps.py`: supported step types and field metadata
- `catalog/build.py`: context catalog JSON for frontend consumption
- `events/registry.py`: trigger registration
- `events/builtin.py`: built-in event specs
- `events/context_catalog.py`: event context variable definitions
- `events/policies.py`: trigger-specific step-type restrictions

### Runtime and worker scheduling

- `services/definitions.py`: format + compile + persist definitions
- `services/dispatch.py`: select matching definitions and enqueue work
- `services/runtime.py`: checkpointed execution and approval resolution
- `services/worker.py`: dedicated worker loop, lease handling, retries, stale recovery
- `services/graph.py`: compiled-IR graph adapter for backend graph consumers

Engine modules:

- `engine/executor.py`: deterministic step execution
- `engine/eval.py`: expression and condition evaluation
- `engine/adapters.py`: email and webhook adapter interfaces / implementations
- `engine/context.py`: runtime event/vars context
- `engine/types.py`: execution result datatypes

### Views and URLs

Main user-facing surfaces live in:

- `views/definitions.py`: create/edit definition pages
- `views/context_catalog.py`: context catalog API
- `views/graph_from_yaml_api.py`: compile raw YAML to graph JSON without saving
- `views/graph_api.py`: graph JSON for saved definitions
- `views/runs.py`, `views/instances.py`, `views/approvals.py`: runtime inspection and control
- `urls.py`: app routing

## Frontend Architecture

The frontend entry point is:

- `trustpoint/workflows2/frontend/src/workflow_editor/index.js`

The bundle is built by:

- `trustpoint/workflows2/frontend/build.mjs`

and written to:

- `trustpoint/static/js/workflows2/editor_bundle.js`

### Folder ownership

`frontend/src/workflow_editor/page`

- page bootstrapping
- DOM lookup
- graph callback wiring

`frontend/src/workflow_editor/editor`

- CodeMirror YAML editor controller

`frontend/src/workflow_editor/document`

- YAML parsing helpers
- document mutation primitives
- flow manipulation
- condition-tree helpers
- variable availability analysis
- expression insertion templates

`frontend/src/workflow_editor/document/operations`

- semantic YAML mutations used by graph and guide actions

`frontend/src/workflow_editor/guide`

- semantic context derivation
- guide rendering
- guide action handling
- structured guide sections

`frontend/src/workflow_editor/graph`

- draft graph parsing from raw YAML
- layout
- SVG rendering
- canvas interactions
- overlay rendering
- overlay and interaction action handling

`frontend/src/workflow_editor/logic`

- nested logic condition tree rendering

`frontend/src/workflow_editor/steps`

- structured editors for step-specific content

`frontend/src/workflow_editor/variables`

- inline runtime picker for scoped vars and expression snippets

`frontend/src/workflow_editor/ui`

- guide drawer shell
- graph expansion
- issues panel

`frontend/src/workflow_editor/shared`

- small DOM, HTTP, and general helpers

## Frontend Data Flow

The main workspace controller is:

- `frontend/src/workflow_editor/page/workflow_editor_workspace.js`

It coordinates:

- YAML editor changes
- semantic guide context
- issues panel updates
- draft graph refreshes
- graph and guide action handlers

Current editor behavior:

- YAML changes update semantic context immediately
- the graph preview is client-side and draft-tolerant
- guide and graph actions both mutate YAML through shared document operations
- the save form still posts YAML back to Django as the final source of truth

This separation is important:

- the frontend draft graph is a usability feature
- the backend compiler is the authoritative validity check

## Important Shared Invariants

These are the things refactors must preserve.

### 1. YAML is canonical

- Graph edits must become YAML edits.
- Guide actions must become YAML edits.
- Save & Compile persists formatted YAML and compiled IR.

### 2. The draft graph must be tolerant

`draft_workflow_graph_parser.js` intentionally renders partial workflow structure even when the YAML is incomplete.

The graph should degrade into warnings and issues, not disappear unnecessarily.

### 3. Variable availability must stay consistent across frontend and backend

This logic exists in two places on purpose:

- frontend: `document/variable_availability.js`
- backend: `WorkflowCompiler._compute_available_vars_before_step()`

They must stay semantically aligned.

Current rule:

- a step can only rely on vars guaranteed across every incoming reachable path
- `compute` may reference values assigned earlier in the same compute step
- `set` does not get same-step sequential visibility

### 4. Catalog metadata drives the editor

The frontend should not hardcode step definitions when catalog metadata already exists.

If you add a field or step, update the catalog first.

## How To Extend The System

### Add a new step type

Touch at least these areas:

1. `compiler/step_types.py`
2. `catalog/steps.py`
3. `compiler/lint.py`
4. `compiler/compiler.py`
5. `engine/executor.py`
6. `document/variable_availability.js` if the step writes vars
7. graph/guide structured editors if it needs a managed UI
8. tests
9. docs

### Add a new expression function

Touch:

1. `compiler/expr.py`
   Add the function to the allowlist and the visible function groups.
2. `engine/eval.py`
   Implement execution in `_call()`.
3. `frontend/src/workflow_editor/document/expression_insertions.js`
   Add a good insertion template for the inline picker.

The guide and inline runtime picker read function metadata from the catalog automatically once the compiler function groups are updated.

### Add a new condition operator

Touch:

1. `compiler/conditions.py`
2. guide logic/condition rendering
3. graph logic tree rendering
4. condition tree document operations
5. tests

### Add a new event trigger

Touch:

1. `events/builtin.py` or custom registry bootstrapping
2. `events/context_catalog.py`
3. `events/policies.py` if the trigger restricts step types
4. tests

The editor guide and runtime context displays consume the event catalog automatically.

## Public APIs Used By The Editor

- `api/context-catalog/`
  Returns event, step, and DSL metadata for guide and graph UI.
- `api/graph-from-yaml/`
  Compiles raw YAML to graph JSON without saving.
- `api/definitions/<id>/graph/`
  Returns graph JSON for persisted definitions.

The current editor relies primarily on the client-side draft graph path for immediate feedback, but these endpoints remain useful for backend-driven views and future integration points.

## Tests and Verification

The main backend test coverage currently lives in:

- `tests/test_compiler.py`
- `tests/test_executor.py`
- `tests/test_dispatch.py`
- `tests/test_worker.py`
- `tests/test_crash_recovery.py`
- `tests/test_workflow2_bundle_approval_reject.py`

Useful commands:

```bash
cd trustpoint/workflows2/frontend
npm run build
```

```bash
python trustpoint/manage.py test workflows2.tests.test_compiler
```

For larger changes, also run the relevant runtime tests, not just compiler tests.

## Good Places To Look First

If you need to change a specific behavior, start here:

- definition save/compile flow: `services/definitions.py`
- core compiler behavior: `compiler/compiler.py`
- expression parsing: `compiler/expr.py`
- runtime step execution: `engine/executor.py`
- event and step catalog data: `catalog/build.py`, `catalog/steps.py`, `events/*`
- editor bootstrapping: `frontend/src/workflow_editor/page/workflow_editor_workspace.js`
- graph behavior: `frontend/src/workflow_editor/graph/*`
- guide behavior: `frontend/src/workflow_editor/guide/*`
- YAML mutation behavior: `frontend/src/workflow_editor/document/operations/*`

## Current Concept Summary

If you only remember five things about this app, remember these:

1. Definitions are authored in YAML and saved as YAML plus compiled IR.
2. The compiler is strict about reachability, outcome routing, and variable availability.
3. The runtime is DB-backed and step-by-step durable.
4. The frontend is document-centered: guide and graph both mutate YAML through shared operations.
5. The context catalog is the shared contract between backend metadata and frontend editing UX.
