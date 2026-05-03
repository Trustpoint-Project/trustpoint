export function getStepFieldSuggestions(stepType, fieldKey) {
  const key = `${String(stepType || '')}:${String(fieldKey || '')}`;

  switch (key) {
    case 'webhook:headers':
      return [
        {
          label: 'Request ID',
          value: 'x-request-id: ${event.meta.request_id}',
          description: 'Forward the event request id as a correlation header.',
        },
        {
          label: 'JSON auth',
          value: 'content-type: application/json\nauthorization: Bearer ${vars.api_token}',
          description: 'Common JSON API headers with a bearer token.',
        },
      ];

    case 'webhook:body':
      return [
        {
          label: 'Device payload',
          value: 'device_id: ${event.device.id}\nserial_number: ${event.device.serial_number}',
          description: 'Basic device identifiers from the event payload.',
        },
        {
          label: 'Workflow result',
          value: 'result: ${vars.result}\nmessage: ${vars.message}',
          description: 'Send workflow variables collected earlier in the run.',
        },
      ];

    case 'approval:approved_outcome':
      return [
        {
          label: 'approved',
          value: 'approved',
          description: 'Explicit approval outcome naming.',
        },
        {
          label: 'ok',
          value: 'ok',
          description: 'Short success-oriented routing outcome.',
        },
        {
          label: 'continue',
          value: 'continue',
          description: 'Continue to the next normal path.',
        },
      ];

    case 'approval:rejected_outcome':
      return [
        {
          label: 'rejected',
          value: 'rejected',
          description: 'Explicit rejection outcome naming.',
        },
        {
          label: 'fail',
          value: 'fail',
          description: 'Route to a failure path.',
        },
        {
          label: 'needs_review',
          value: 'needs_review',
          description: 'Escalate to a follow-up review path.',
        },
      ];

    default:
      return [];
  }
}
