from __future__ import annotations

from workflows.models import WorkflowInstance
from workflows.services.executors import ExecStatus, NodeExecutorFactory, NodeResult


def advance_instance(
    instance: WorkflowInstance,
    signal: str | None = None,
) -> None:
    """Drive an instance forward until.

      • an executor asks us to WAIT (e.g. Approval),
      • an executor returns a terminal status (APPROVED / REJECTED / COMPLETED / FAIL),
      • or we reach the end of nodes (COMPLETED).

    Executors are responsible for business outcomes (e.g., deciding “this is REJECTED”
    or “this is APPROVED (terminal)”). The engine interprets those outcomes and
    moves the pointer / sets state accordingly.
    """
    if instance.finalized:
        return

    # Kick off if brand new
    if instance.state == WorkflowInstance.STATE_STARTING:
        instance.state = WorkflowInstance.STATE_RUNNING
        instance.save(update_fields=['state'])

    # Main driver loop
    while True:
        nodes = instance.definition.definition.get('nodes', [])
        try:
            node_meta = next(n for n in nodes if n['id'] == instance.current_step)
        except StopIteration:
            # Safety: no such node → treat as completed
            instance.state = WorkflowInstance.STATE_COMPLETED
            break

        node_type = node_meta.get('type')
        executor = NodeExecutorFactory.create(node_type)
        result: NodeResult = executor.execute(instance, signal)

        # Stash per-step context if provided
        if result.context is not None:
            sc = dict(instance.step_contexts or {})
            sc[str(instance.current_step)] = result.context
            instance.step_contexts = sc
            instance.save(update_fields=['step_contexts'])

        # Interpret result
        if result.status == ExecStatus.PASSED:
            # proceed to next node (if any) and keep running
            next_step = instance.get_next_step()
            if next_step:
                instance.current_step = next_step
                instance.state = WorkflowInstance.STATE_RUNNING
                instance.save(update_fields=['current_step', 'state'])
                signal = None  # one-shot
                continue

            # End of nodes (no approvals are involved at this point)
            instance.state = WorkflowInstance.STATE_COMPLETED
            break

        if result.status == ExecStatus.WAITING:
            # Pause. Approval nodes set AwaitingApproval; others may set generic waits later.
            if node_type == 'Approval':
                instance.state = WorkflowInstance.STATE_AWAITING
                instance.save(update_fields=['state'])
            break

        if result.status == ExecStatus.APPROVED:
            # Terminal approval: mark Approved and *prepare* to continue later.
            # Move pointer to the NEXT node now so a later call resumes seamlessly.
            next_step = instance.get_next_step()
            if next_step:
                instance.current_step = next_step
                instance.save(update_fields=['current_step'])
            instance.state = WorkflowInstance.STATE_APPROVED
            instance.save(update_fields=['state'])
            break

        if result.status == ExecStatus.REJECTED:
            instance.state = WorkflowInstance.STATE_REJECTED
            instance.save(update_fields=['state'])
            break

        if result.status == ExecStatus.COMPLETED:
            instance.state = WorkflowInstance.STATE_COMPLETED
            break

        # result.status == FAIL (generic failure)
        instance.state = WorkflowInstance.STATE_FAILED
        break
