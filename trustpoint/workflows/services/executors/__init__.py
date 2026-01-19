"""Workflow step executor registration."""

from __future__ import annotations

from workflows.services.executors.approval import ApprovalExecutor
from workflows.services.executors.email import EmailExecutor
from workflows.services.executors.factory import StepExecutorFactory
from workflows.services.executors.logic import LogicExecutor
from workflows.services.executors.webhook import WebhookExecutor


def register_executors() -> None:
    """Register all supported step executors.

    This function is idempotent.
    """
    StepExecutorFactory.register('Approval', ApprovalExecutor)
    StepExecutorFactory.register('Email', EmailExecutor)
    StepExecutorFactory.register('Webhook', WebhookExecutor)
    StepExecutorFactory.register('Logic', LogicExecutor)
