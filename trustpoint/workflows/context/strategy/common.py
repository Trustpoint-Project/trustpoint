# workflows/context/strategy/common.py

def common_workflow_group(instance) -> dict:
    return {
        "name": "Workflow",
        "vars": [
            {"path": "ctx.workflow.id", "label": "Workflow ID", "sample": str(instance.pk)},
            {"path": "ctx.workflow.name", "label": "Workflow Name", "sample": instance.definition.name},
        ],
    }


def common_instance_group(instance) -> dict:
    return {
        "name": "Instance",
        "vars": [
            {"path": "ctx.instance.instance_state", "label": "Instance State", "sample": instance.state},
        ],
    }
