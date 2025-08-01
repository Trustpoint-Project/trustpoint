# workflows/services/engine.py


from workflows.models import WorkflowInstance
from workflows.services.executors import NodeExecutorFactory


def advance_instance(
    instance: WorkflowInstance,
    signal: str | None = None,
) -> None:
    """Move a WorkflowInstance along to its next node/state.

    Using the NodeExecutorFactory to look up the right executor.
    """
    definition_meta = instance.definition.definition
    node_meta = next(
        n for n in definition_meta['nodes']
        if n['id'] == instance.current_node
    )
    executor = NodeExecutorFactory.create(node_meta['type'])
    next_node, next_state = executor.execute(instance, signal)
    instance.current_node = next_node or instance.current_node
    instance.state = next_state
    instance.save(update_fields=['current_node', 'state'])
