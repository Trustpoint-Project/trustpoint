"""Built-in workflow node executors registry."""

from __future__ import annotations

from workflows.services.executors.approval import ApprovalExecutor
from workflows.services.executors.email import EmailExecutor
from workflows.services.executors.factory import NodeExecutorFactory
from workflows.services.executors.webhook import WebhookExecutor

# Register built-ins here (imported by AppConfig.ready)
NodeExecutorFactory.register('Approval', ApprovalExecutor)
NodeExecutorFactory.register('Email', EmailExecutor)
NodeExecutorFactory.register('Webhook', WebhookExecutor)
