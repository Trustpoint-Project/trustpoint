# workflows/services/executors.py

from util.email_service import EmailService

from workflows.models import WorkflowInstance


class NodeExecutorFactory:
    """Factory Method: map node types to their executor classes."""
    _registry: dict[str, type['AbstractNodeExecutor']] = {}

    @classmethod
    def register(
        cls,
        node_type: str,
        executor_cls: type['AbstractNodeExecutor'],
    ) -> None:
        cls._registry[node_type] = executor_cls

    @classmethod
    def create(cls, node_type: str) -> 'AbstractNodeExecutor':
        executor_cls = cls._registry.get(node_type)
        if not executor_cls:
            raise ValueError(f'No executor registered for node type {node_type!r}')
        return executor_cls()


class AbstractNodeExecutor:
    """Base for all executors, defining core states and the 2‑tuple API."""

    STATE_NOT_STARTED = 'not_started_yet'
    STATE_WAITING     = 'waiting'
    STATE_COMPLETED   = 'completed'
    STATE_ERROR       = 'error'

    def execute(
        self,
        instance: WorkflowInstance,
        signal: str | None = None,
    ) -> tuple[str | None, str]:
        """1) Mark this node as waiting.
        2) Call do_execute().
        3) Return (next_node, state).
        """
        node_id = instance.current_node

        # 1) mark waiting
        instance.step_states[node_id] = self.STATE_WAITING
        instance.save(update_fields=['step_states'])

        # 2) delegate to subclass
        next_node, state = self.do_execute(instance, signal)

        # 3) sanity‑check
        allowed = self.core_states() | self.extra_states()
        if state not in allowed:
            raise ValueError(
                f'{self.__class__.__name__}.do_execute returned invalid state {state!r}; '
                f'allowed: {allowed}'
            )

        return next_node, state

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        """Subclasses implement. Return (next_node, state)."""
        raise NotImplementedError

    @classmethod
    def core_states(cls) -> set[str]:
        return {
            cls.STATE_NOT_STARTED,
            cls.STATE_WAITING,
            cls.STATE_COMPLETED,
            cls.STATE_ERROR,
        }

    @classmethod
    def extra_states(cls) -> set[str]:
        """Override to add step‑specific states."""
        return set()


class ApprovalExecutor(AbstractNodeExecutor):
    """Handles Approval nodes: waiting → approved/rejected."""

    STATE_APPROVED = 'approved'
    STATE_REJECTED = 'rejected'

    @classmethod
    def extra_states(cls) -> set[str]:
        return {cls.STATE_APPROVED, cls.STATE_REJECTED}

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        definition  = instance.definition.definition
        transitions = definition.get('transitions', [])
        node_id     = instance.current_node
        prev_state  = instance.step_states.get(node_id, self.STATE_NOT_STARTED)

        # first arrival → send email & stay waiting
        if prev_state == self.STATE_NOT_STARTED:
            # TODO: send your approval‑request email here
            return node_id, self.STATE_WAITING

        # on Approved → move on or complete
        if signal == 'Approved':
            approved = next(
                (
                    t for t in transitions
                    if t['from'] == node_id and t.get('on') in ('Approved', 'next')
                ),
                None
            )
            if approved and approved.get('to'):
                return approved['to'], self.STATE_APPROVED
            return None, self.STATE_APPROVED

        # on Rejected → stop
        if signal == 'Rejected':
            return None, self.STATE_REJECTED

        # otherwise remain in whatever state we were in
        return node_id, prev_state


class ConditionExecutor(AbstractNodeExecutor):
    """Evaluate a condition and branch immediately."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        cfg       = instance.payload.get('current_node_config', {})
        next_node = cfg.get('params', {}).get('next')
        return next_node, self.STATE_COMPLETED


class EmailExecutor(AbstractNodeExecutor):
    """Send a multipart email; skip or error if needed."""

    STATE_SKIPPED = 'skipped'
    STATE_ERROR   = 'error'

    @classmethod
    def extra_states(cls) -> set[str]:
        return {cls.STATE_SKIPPED, cls.STATE_ERROR}

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None = None,
    ) -> tuple[str | None, str]:
        cfg    = instance.payload.get('current_node_config', {})
        params = cfg.get('params', {})

        raw = params.get('to') or params.get('recipients')
        if isinstance(raw, str):
            to_addrs = [a.strip() for a in raw.split(',') if a.strip()]
        elif isinstance(raw, list):
            to_addrs = raw
        else:
            to_addrs = []

        if not to_addrs:
            return None, self.STATE_SKIPPED

        try:
            EmailService.send_email(
                subject=params.get('subject', ''),
                to=to_addrs,
                template_name=params.get('template', ''),
                context=params.get('context', {}),
                cc=params.get('cc'),
                bcc=params.get('bcc'),
                attachments=params.get('attachments'),
            )
        except Exception:
            return None, self.STATE_ERROR

        return cfg.get('params', {}).get('next'), self.STATE_COMPLETED


class WebhookExecutor(AbstractNodeExecutor):
    """Invoke an external HTTP endpoint, then complete."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        cfg = instance.payload.get('current_node_config', {})
        # TODO: perform HTTP call here
        return cfg.get('params', {}).get('next'), self.STATE_COMPLETED


class TimerExecutor(AbstractNodeExecutor):
    """Synchronous timer stub: immediately complete."""

    def do_execute(
        self,
        instance: WorkflowInstance,
        signal: str | None,
    ) -> tuple[str | None, str]:
        cfg = instance.payload.get('current_node_config', {})
        # TODO: schedule real timer if needed
        return cfg.get('params', {}).get('next'), self.STATE_COMPLETED


# Register all executors
NodeExecutorFactory.register('Approval',   ApprovalExecutor)
NodeExecutorFactory.register('Condition',  ConditionExecutor)
NodeExecutorFactory.register('Email',      EmailExecutor)
NodeExecutorFactory.register('Webhook',    WebhookExecutor)
NodeExecutorFactory.register('Timer',      TimerExecutor)
