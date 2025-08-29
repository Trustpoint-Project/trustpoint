"""Built-in workflow node executors.

This package registers the default executors with the NodeExecutorFactory
when imported. Additional executors may be added here in the future.
"""

from __future__ import annotations

from workflows.services.executors.approval import ApprovalExecutor
from workflows.services.executors.email import EmailExecutor
from workflows.services.executors.factory import NodeExecutorFactory

# Register built-ins here (imported by AppConfig.ready)
NodeExecutorFactory.register('Approval', ApprovalExecutor)
NodeExecutorFactory.register('Email', EmailExecutor)

# Stubs you may implement later:
# NodeExecutorFactory.register("Webhook", WebhookExecutor)  # noqa: ERA001
# NodeExecutorFactory.register("Timer", TimerExecutor)  # noqa: ERA001
# NodeExecutorFactory.register("Condition", ConditionExecutor)  # noqa: ERA001
