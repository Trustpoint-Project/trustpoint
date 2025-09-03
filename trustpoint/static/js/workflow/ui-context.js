// static/js/ui-context.js
// Exports: fetchContextCatalog, attachVarPicker
// Safe, static catalog for inserting {{ ctx.<path> }} variables.
// Matches contexts produced by workflows.services.context.build_context().

let _catalogCache = null;

export async function fetchContextCatalog() {
  if (_catalogCache) return _catalogCache;
  _catalogCache = {
    usage: 'Insert variables using {{ ctx.<path> }}, e.g. {{ ctx.workflow.id }}',
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
          { key: 'csr.subject',             label: 'CSR Subject' },
          { key: 'csr.common_name',         label: 'Common Name' },
          { key: 'csr.sans',                label: 'SubjectAltNames' },
          { key: 'csr.public_key_type',     label: 'Public Key Type' },
        ],
      },
      {
        key: 'vars', label: 'Saved Vars (from steps)', vars: [
          // This is a placeholder group; concrete keys are user-defined.
          // Users can still type {{ ctx.vars.<their_key> }} manually.
        ],
      },
    ],
  };
  return _catalogCache;
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
    const path = select.value; // e.g. 'workflow.id'
    if (!path) return;
    insertAtCaret(targetInput, `{{ ctx.${path} }}`);
    // reset and notify state
    select.selectedIndex = 0;
    targetInput.dispatchEvent(new Event('input', { bubbles: true }));
    targetInput.focus();
  };

  const help = document.createElement('div');
  help.className = 'form-text';
  help.textContent = catalog?.usage || 'Use {{ ctx.<path> }} to render variables.';

  wrap.appendChild(select);
  wrap.appendChild(help);
  container.appendChild(wrap);
}

function insertAtCaret(el, text) {
  if (!el) return;
  const isText = el.tagName === 'TEXTAREA' || (el.tagName === 'INPUT' && (el.type === 'text' || el.type === 'email'));
  if (!isText) return;

  const start = el.selectionStart ?? el.value.length;
  const end   = el.selectionEnd ?? el.value.length;
  const before = el.value.slice(0, start);
  const after  = el.value.slice(end);
  el.value = before + text + after;

  const pos = before.length + text.length;
  try { el.setSelectionRange(pos, pos); } catch {}
}
