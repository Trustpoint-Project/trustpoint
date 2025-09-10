// static/js/ui-context.js
// Exports: buildDesignTimeCatalog, fetchContextCatalog, attachVarPicker
// Purpose: Provide a design-time variable catalog for the wizard's insert picker.
// Includes dynamic step entries under ctx.steps_safe and a helper group for ctx.step_names.

let _lastCacheKey = null;
let _catalogCache = null;

/**
 * Return a design-time catalog object that mirrors what will be available at runtime
 * on `ctx.*`, including dynamic step safe names.
 *
 * @param {object} opts
 * @param {object} opts.state - the wizard state (we use state.steps to synthesize step entries)
 */
export function buildDesignTimeCatalog({ state }) {
  const stepCount = Array.isArray(state?.steps) ? state.steps.length : 0;

  // Simple cache keyed by count; extend if you later include step titles, etc.
  const cacheKey = `v2::steps:${stepCount}`;
  if (_catalogCache && _lastCacheKey === cacheKey) return _catalogCache;

  // Build dynamic step entries
  const stepVars = [];
  for (let i = 0; i < stepCount; i += 1) {
    const safe = `step_${i + 1}`;
    // Anchors authors can expand from:
    stepVars.push({ key: `steps_safe.${safe}`,            label: `${safe} (all)` });
    stepVars.push({ key: `steps_safe.${safe}.outputs`,    label: `${safe}.outputs` });
    stepVars.push({ key: `steps_safe.${safe}.status`,     label: `${safe}.status` });
    stepVars.push({ key: `steps_safe.${safe}.ok`,         label: `${safe}.ok` });
    stepVars.push({ key: `steps_safe.${safe}.error`,      label: `${safe}.error` });
  }

  _catalogCache = {
    usage: 'Insert variables using {{ ctx.<path> }}, e.g. {{ ctx.workflow.id }} or {{ ctx.steps_safe.step_2.outputs.status }}',
    groups: [
      {
        key: 'workflow', label: 'Workflow', vars: [
          { key: 'workflow.id',      label: 'Workflow ID' },
          { key: 'workflow.name',    label: 'Workflow Name' },
          { key: 'workflow.version', label: 'Workflow Version (if present)' },
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
      // NEW: Steps (safe)
      {
        key: 'steps_safe',
        label: 'Steps (safe)',
        vars: stepVars,
      },
      // NEW: helper mapping raw -> safe (authors can see how to reference a given step id)
      {
        key: 'step_names',
        label: 'Step name mapping',
        vars: (function () {
          const out = [];
          for (let i = 0; i < stepCount; i += 1) {
            const raw = `step-${i + 1}`;
            const safe = `step_${i + 1}`;
            out.push({ key: `step_names.${raw}`, label: `${raw} → ${safe}` });
          }
          return out;
        }()),
      },
      {
        key: 'vars', label: 'Saved Vars', vars: [
          // Anchors only; authors will know their specific keys.
          { key: 'vars',         label: 'vars (whole map)' },
          { key: 'vars.answer',  label: 'example: vars.answer' },
        ],
      },
    ],
  };

  _lastCacheKey = cacheKey;
  return _catalogCache;
}

// Backwards-compatible wrapper. Call with the wizard `state`.
export async function fetchContextCatalog(state) {
  return buildDesignTimeCatalog({ state });
}

// Adds a compact picker next to a label; inserts token at the caret into an
// <input> or <textarea> and keeps the field editable/copyable.
export function attachVarPicker({ container, targetInput, catalog }) {
  if (!container || !targetInput) return;

  const wrap = document.createElement('div');
  wrap.className = 'mt-1';

  const select = document.createElement('select');
  select.className = 'form-select form-select-sm';
  const ph = new Option('Insert variable…', '', true, true);
  ph.disabled = true;
  select.add(ph);

  for (const g of (catalog?.groups || [])) {
    const og = document.createElement('optgroup');
    og.label = g.label || g.key;
    for (const v of (g.vars || [])) {
      og.appendChild(new Option(v.label || v.key, v.key));
    }
    select.appendChild(og);
  }

  select.onchange = () => {
    const path = select.value; // e.g. 'steps_safe.step_2.outputs.status'
    if (!path) return;
    insertAtCaret(targetInput, `{{ ctx.${path} }}`);
    // reset and notify state
    select.selectedIndex = 0;
    targetInput.dispatchEvent(new Event('input', { bubbles: true }));
    targetInput.focus();
  };

  const help = document.createElement('div');
  help.className = 'form-text';
  help.textContent =
    catalog?.usage ||
    'Use {{ ctx.<path> }} to render variables.';

  wrap.appendChild(select);
  wrap.appendChild(help);
  container.appendChild(wrap);
}

function insertAtCaret(el, text) {
  if (!el) return;
  const isText =
    el.tagName === 'TEXTAREA' ||
    (el.tagName === 'INPUT' && (el.type === 'text' || el.type === 'email'));
  if (!isText) return;

  const start = el.selectionStart ?? el.value.length;
  const end   = el.selectionEnd ?? el.value.length;
  const before = el.value.slice(0, start);
  const after  = el.value.slice(end);
  el.value = before + text + after;

  const pos = before.length + text.length;
  try { el.setSelectionRange(pos, pos); } catch {}
}
