// static/js/workflow/ui-context.js
// Design-time ctx catalog for the variable panel (no step_names, no steps_safe).
// We expose ctx.steps.step_1, step_2, ... only, and only show webhook subkeys for webhook steps.

let _lastCacheKey = null;
let _catalogCache = null;

export function buildDesignTimeCatalog({ state }) {
  const steps = Array.isArray(state?.steps) ? state.steps : [];
  const stepCount = steps.length;

  // Incorporate step types into the cache key so we rebuild when types change
  const typeSig = steps.map(s => s?.type || '').join('|');
  const cacheKey = `v4::steps:${stepCount}::${typeSig}`;
  if (_catalogCache && _lastCacheKey === cacheKey) return _catalogCache;

  const stepVars = [];
  for (let i = 0; i < stepCount; i += 1) {
    const safe = `step_${i + 1}`;
    const t = (steps[i] && steps[i].type) || '';

    stepVars.push({ key: `steps.${safe}`,         label: `${safe} (all)` });
    stepVars.push({ key: `steps.${safe}.outputs`, label: `${safe}.outputs` });
    stepVars.push({ key: `steps.${safe}.status`,  label: `${safe}.status` });
    stepVars.push({ key: `steps.${safe}.ok`,      label: `${safe}.ok` });
    stepVars.push({ key: `steps.${safe}.error`,   label: `${safe}.error` });

    // Only show webhook convenience keys if this step is a Webhook
    if (t === 'Webhook') {
      stepVars.push({ key: `steps.${safe}.outputs.webhook.status`, label: `${safe}.webhook.status` });
      stepVars.push({ key: `steps.${safe}.outputs.webhook.text`,   label: `${safe}.webhook.text` });
    }
  }

  _catalogCache = {
    usage: 'Insert variables using {{ ctx.<path> }}, e.g. {{ ctx.workflow.id }} or {{ ctx.steps.step_2.outputs.webhook.status }}',
    groups: [
      {
        key: 'workflow', label: 'Workflow', vars: [
          { key: 'workflow.id',   label: 'Workflow ID' },
          { key: 'workflow.name', label: 'Workflow Name' },
        ],
      },
      {
        key: 'instance', label: 'Instance', vars: [
          { key: 'instance.id',           label: 'Instance ID' },
          { key: 'instance.state',        label: 'Instance State' },
          { key: 'instance.current_step', label: 'Current Step ID' },
        ],
      },
      {
        key: 'payload', label: 'Payload', vars: [
          { key: 'payload.protocol',    label: 'Protocol' },
          { key: 'payload.operation',   label: 'Operation' },
          { key: 'payload.ca_id',       label: 'CA ID' },
          { key: 'payload.domain_id',   label: 'Domain ID' },
          { key: 'payload.device_id',   label: 'Device ID' },
          { key: 'payload.fingerprint', label: 'CSR Fingerprint' },
        ],
      },
      {
        key: 'csr', label: 'CSR (parsed)', vars: [
          { key: 'csr.subject',         label: 'CSR Subject' },
          { key: 'csr.common_name',     label: 'Common Name' },
          { key: 'csr.sans',            label: 'SubjectAltNames' },
          { key: 'csr.public_key_type', label: 'Public Key Type' },
        ],
      },
      { key: 'steps', label: 'Steps', vars: stepVars },
      {
        key: 'vars', label: 'Saved Vars', vars: [
          { key: 'vars', label: 'vars (whole map)' },
        ],
      },
    ],
  };

  _lastCacheKey = cacheKey;
  return _catalogCache;
}

export async function fetchContextCatalog(state) {
  return buildDesignTimeCatalog({ state });
}
