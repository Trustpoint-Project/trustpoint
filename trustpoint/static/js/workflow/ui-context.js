// static/js/workflow/ui-context.js
// Design-time ctx catalog for the variable panel (step-type aware).
// Exposes ctx.steps.step_1, step_2, ... and only shows per-type outputs where applicable.

let _lastSig = null;
let _cache = null;

/** Build a stable signature of steps for caching. */
function stepsSignature(steps) {
  // type + presence of params keys (cheap but stable enough)
  return (steps || [])
    .map(s => `${s.type}|${Object.keys(s.params || {}).sort().join(',')}`)
    .join('||');
}

export function buildDesignTimeCatalog({ state }) {
  const steps = Array.isArray(state?.steps) ? state.steps : [];
  const sig = `v4::${stepsSignature(steps)}`;
  if (_cache && _lastSig === sig) return _cache;

  const stepVars = [];
  for (let i = 0; i < steps.length; i += 1) {
    const safe = `step_${i + 1}`;
    const st = steps[i] || {};
    const type = String(st.type || '');

    // Always useful:
    stepVars.push({ key: `steps.${safe}`,         label: `${safe} (all)` });
    stepVars.push({ key: `steps.${safe}.outputs`, label: `${safe}.outputs` });
    stepVars.push({ key: `steps.${safe}.status`,  label: `${safe}.status` });
    stepVars.push({ key: `steps.${safe}.ok`,      label: `${safe}.ok` });
    stepVars.push({ key: `steps.${safe}.error`,   label: `${safe}.error` });

    // Type-specific hints
    if (type === 'Webhook') {
      stepVars.push({ key: `steps.${safe}.outputs.webhook.status`, label: `${safe}.outputs.webhook.status` });
      stepVars.push({ key: `steps.${safe}.outputs.webhook.text`,   label: `${safe}.outputs.webhook.text` });
      stepVars.push({ key: `steps.${safe}.outputs.webhook.json`,   label: `${safe}.outputs.webhook.json` });
      stepVars.push({ key: `steps.${safe}.outputs.webhook.headers`,label: `${safe}.outputs.webhook.headers` });
    }
    if (type === 'Email') {
      stepVars.push({ key: `steps.${safe}.outputs.mode`,    label: `${safe}.outputs.mode` });
      stepVars.push({ key: `steps.${safe}.outputs.subject`, label: `${safe}.outputs.subject` });
      stepVars.push({ key: `steps.${safe}.outputs.email`,   label: `${safe}.outputs.email` });
    }
    if (type === 'Approval') {
      // keep generic for now; can add more if your approval step writes outputs
    }
    if (type === 'Condition') {
      // if your condition step writes outputs, surface them here similarly
    }
  }

  _cache = {
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

  _lastSig = sig;
  return _cache;
}

// Backward compat (used by VarPanel)
export async function fetchContextCatalog(state) {
  return buildDesignTimeCatalog({ state });
}
