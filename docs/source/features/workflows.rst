.. _workflow-engine:

===============
Workflow Engine
===============

Trustpoint workflows automate decisions around devices, certificates, and
enrollment requests. They can notify operators, call external systems, pause an
enrollment for approval, or intentionally end a request as approved, rejected,
timed out, stopped, or finished.

Workflows are YAML-first. The interactive editor provides a YAML editor, graph
view, and structured controls, but the YAML remains the source of truth.

.. warning::

   The workflow engine is part of the Trustpoint technology preview. Review
   workflows carefully before using them for security-sensitive automation.


Mental Model
============

A workflow definition has five important parts:

``trigger``
    Selects the event that starts the workflow, for example
    ``device.created`` or ``est.simpleenroll``.

``trigger.sources``
    Limits where the workflow applies. Use ``trustpoint: true`` for a global
    workflow, or restrict it by CA, domain, or device ID.

``apply``
    Optional preconditions. Every condition in the list must match.

``workflow.start``
    The first step to execute.

``workflow.steps`` and ``workflow.flow``
    The named steps and their transitions.

At runtime, expressions can read:

``event``
    The immutable event payload.

``vars``
    Mutable workflow state written by previous steps.

Expressions use ``${...}``, for example ``${event.device.common_name}`` or
``${vars.http_status}``.


Small Example
=============

This workflow asks an operator to approve an EST simpleenroll request:

.. code-block:: yaml

   schema: trustpoint.workflow.v2
   name: Approve EST simpleenroll
   enabled: true

   trigger:
     on: est.simpleenroll
     sources:
       trustpoint: true
       ca_ids: []
       domain_ids: []
       device_ids: []

   apply:
     - exists: ${event.device}

   workflow:
     start: approval_gate

     steps:
       approval_gate:
         type: approval
         title: Approve certificate request
         timeout_seconds: 3600

     flow: []

When the approval is accepted, the workflow ends as ``approved``. When it is
rejected, it ends as ``rejected``. When it expires, it ends as ``timed_out``.
No special end step is needed.


Step Types
==========

Use these step types to build workflows:

``approval``
    Wait for an operator decision. Approved and rejected outcomes may either end
    directly or route to another step. Timeout may route to follow-up handling,
    but that route must end with an explicit non-continuing result.

``logic``
    Evaluate ordered conditions and route by outcome.

``set``
    Write literal or templated values into ``vars``.

``compute``
    Write ``vars`` using safe expressions such as ``add``, ``round``,
    ``concat``, ``lower``, or ``upper``.

``webhook``
    Call an HTTP endpoint and optionally capture response data into ``vars``.

``email``
    Send an email through the configured Django email backend.

``notification``
    Create a Trustpoint notification.

``set_status``
    Explicitly set the workflow result to ``finished``, ``approved``,
    ``rejected``, ``timed_out``, ``stopped``, or ``paused``.

``error`` is not a workflow-authored result. It is reserved for retryable
runtime failures.


Flow and Endings
================

Workflow branches end naturally when a step has no next step. Legacy terminal
tokens such as ``$end`` and ``$reject`` are not used.

Use a normal linear transition for simple flow:

.. code-block:: yaml

   - from: call_api
     to: notify

Use an outcome transition when a step produces outcomes:

.. code-block:: yaml

   - from: route_status
     on: ok
     to: mark_approved

Important rules:

* Every step must be reachable from ``workflow.start``.
* ``logic`` outcomes must be routed.
* ``approval`` approved and rejected outcomes may be routed, but do not have to
  be.
* ``approval`` timeout outcomes may be routed, but every timeout branch must end
  with ``set_status`` as ``rejected``, ``timed_out``, ``stopped``, or
  ``paused``.
* A ``set_status`` terminal result cannot have outgoing flow.
* ``set_status: paused`` must have one linear outgoing flow entry. That target
  becomes the resume point.


Lifecycle States
================

Runs and instances use a small status vocabulary:

``queued`` / ``running``
    Work is waiting or executing.

``awaiting``
    An approval is waiting for an operator.

``paused``
    The workflow intentionally paused and can resume from its stored next step.

``error``
    A retryable runtime error occurred. Operators can resume or stop it.

``finished``
    The branch ended without an explicit business approval or rejection.

``approved`` / ``rejected``
    The workflow ended with a business decision.

``timed_out`` / ``stopped`` / ``cancelled``
    The workflow cannot continue.

For enrollment requests, Trustpoint translates these states into request
decisions:

``approved`` and ``finished``
    Continue the request.

``queued``, ``running``, ``awaiting``, ``paused``, and ``error``
    Wait.

``rejected``
    Reject the request.

``timed_out``, ``stopped``, and ``cancelled``
    Fail the request.


Request Locks
=============

Some enrollment requests use a request lock to avoid duplicate workflow runs
for the same request details. While a run holds the lock, the same request maps
back to that run.

On a terminal run, operators can use **Allow same request again** to release the
lock. This does not change the old result. It only allows identical request
details to create a fresh workflow run later.

The Runs page shows whether a run is locked, released, or released manually.


Operator Views
==============

``Definitions``
    Create, edit, enable, and disable workflows. The saved name comes from the
    YAML ``name`` field.

``Runs``
    Inspect triggered runs, status, event context, source context, instances,
    and request locks. The list supports broad search and filters for status,
    trigger, and request-lock state.

``Waiting``
    Review pending approvals, paused workflows, and retryable runtime errors.
    Paused and errored instances can be resumed from their current step or
    stopped.


Authoring Tips
==============

* Start with one linear workflow and add branches later.
* Keep step IDs stable; use ``title`` for user-facing labels.
* Let a missing next step mean normal completion.
* Use ``set_status`` only when the workflow result itself matters.
* Use ``notification`` for Trustpoint UI notifications and ``email`` for
  external email.
* Use ``compute`` for expressions and ``set`` for direct templated values.
* If the graph and YAML disagree, trust the YAML and the issues panel.
* Keep request-lock releases deliberate; they allow duplicate request details to
  start a new run.
