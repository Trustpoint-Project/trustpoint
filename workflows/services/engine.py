# workflows/services/engine.py

from workflows.models import WorkflowInstance
from workflows.services.executors import AbstractNodeExecutor, NodeExecutorFactory


def advance_instance(
    instance: WorkflowInstance,
    signal: str | None = None,
) -> None:
    """1) Normalize any old step_states entries into plain strings.
    2) Ensure every node in the definition appears (defaulting to NOT_STARTED).
    3) Run the current executor, storing only its returned state.
    4) Recompute the overall WorkflowInstance.state from those strings.
    """
    definition = instance.definition.definition
    nodes      = definition.get('nodes', [])

    # 1) normalize legacy entries
    raw = instance.step_states or {}
    normalized: dict[str, str] = {nid: str(entry) for nid, entry in raw.items()}

    # 2) make sure every node_id is present
    for n in nodes:
        nid = n.get('id')
        normalized.setdefault(nid, AbstractNodeExecutor.STATE_NOT_STARTED)

    instance.step_states = normalized

    # 3) locate metadata for current step & execute
    meta     = next(n for n in nodes if n.get('id') == instance.current_node)
    node_id  = meta['id']
    executor = NodeExecutorFactory.create(meta['type'])
    next_node, new_state = executor.execute(instance, signal)

    # overwrite this node’s state
    instance.step_states[node_id] = new_state

    # advance the pointer
    instance.current_node = next_node or instance.current_node

    # 4) recompute overall instance.state
    all_states = set(instance.step_states.values())
    saw_error = AbstractNodeExecutor.STATE_ERROR in all_states

    # A step is “done” if it’s neither NOT_STARTED nor WAITING
    all_done = all(
        st not in (
            AbstractNodeExecutor.STATE_NOT_STARTED,
            AbstractNodeExecutor.STATE_WAITING,
        )
        for st in all_states
    )

    if saw_error:
        instance.state = WorkflowInstance.STATE_ERROR
    elif all_done:
        instance.state = WorkflowInstance.STATE_COMPLETE
    else:
        instance.state = WorkflowInstance.STATE_PENDING

    instance.save(update_fields=['current_node', 'state', 'step_states'])
