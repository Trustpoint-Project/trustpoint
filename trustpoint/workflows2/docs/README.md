# Workflows 2 Docs

This directory intentionally contains one small docs set with two audiences:

- `USER_GUIDE.md`
  Brief, practical author documentation for people building workflows in YAML or in the editor UI.
- `DEVELOPER_GUIDE.md`
  Architecture and codebase documentation for people extending, debugging, or refactoring `workflows2`.

Use the user guide if you want to answer:

- What does a workflow look like?
- Which step types, conditions, and expressions are supported?
- How do I use the YAML editor, graph, guide drawer, and issues panel?
- What common authoring mistakes does the compiler reject?

Use the developer guide if you want to answer:

- Where does YAML get compiled, validated, saved, and executed?
- Which modules own the editor, guide, graph, runtime, and queue worker?
- How do I add a step type, expression function, event, or editor behavior?
- Which invariants are important enough that refactors must preserve them?

Project-wide invariants worth keeping in mind before you read either guide:

- YAML is the source of truth.
- The graph and guide are editing helpers around YAML, not a second state model.
- The frontend draft graph is intentionally tolerant so authors can keep working while a workflow is incomplete.
- The backend compiler and runtime are authoritative for compile validity and execution semantics.
- Variable availability is path-sensitive: a step may only rely on workflow vars guaranteed on every incoming reachable path.
