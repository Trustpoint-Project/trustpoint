"""Built-in workflow step executors registry."""

from __future__ import annotations

from workflows.services.executors.approval import ApprovalExecutor
from workflows.services.executors.email import EmailExecutor
from workflows.services.executors.factory import StepExecutorFactory
from workflows.services.executors.webhook import WebhookExecutor

# Register built-ins here (imported by AppConfig.ready)
StepExecutorFactory.register('Approval', ApprovalExecutor)
StepExecutorFactory.register('Email', EmailExecutor)
StepExecutorFactory.register('Webhook', WebhookExecutor)
