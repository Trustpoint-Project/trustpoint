// static/js/workflow/executors/logic/ui/assignments.js
import { ui } from '../../index.js';
import { markTemplatable } from '../../../template-fields.js';

function ensureObj(v) {
  return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {};
}

function nextFreeKey(assign) {
  for (let i = 1; i < 1000; i++) {
    const k = `var${i}`;
    if (!(k in assign)) return k;
  }
  return 'var';
}

export function renderAssignments(container, assignObj, onUpdateAssign, touch, opts = {}) {
  container.textContent = '';
  const assign = ensureObj(assignObj);

  const prefix = String(opts.fieldPrefix || '').trim();

  const callUpdate = (next, structural = false) => {
    try { onUpdateAssign?.(next, { structural }); } catch { onUpdateAssign?.(next); }
  };

  const wrap = document.createElement('div');
  wrap.className = 'lg-card';
  if (prefix) wrap.dataset.wwField = `${prefix}-wrap`;

  wrap.appendChild(ui.help('Assignments write to ctx.vars. Values may be JSON or {{ ctx.* }} templates.'));

  const entries = Object.entries(assign);
  if (!entries.length) wrap.appendChild(ui.help('No assignments yet.'));

  entries.forEach(([k, v], idx) => {
    const row = document.createElement('div');
    row.className = 'lg-row mb-2';
    if (prefix) row.dataset.wwField = `${prefix}-row-${idx}`;

    const keyInp = ui.input({
      type: 'text',
      value: k,
      onInput: (newKey) => {
        const nk = String(newKey || '').trim();
        const next = { ...assign };
        const oldVal = next[k];
        delete next[k];
        if (nk) next[nk] = oldVal;
        callUpdate(next, false);
        touch?.();
      },
    });
    if (prefix) keyInp.dataset.wwField = `${prefix}-key-${idx}`;

    const valInp = ui.input({
      type: 'text',
      value: JSON.stringify(v ?? null),
      onInput: (raw) => {
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        const next = { ...assign, [k]: parsed };
        callUpdate(next, false);
        touch?.();
      },
    });
    if (prefix) valInp.dataset.wwField = `${prefix}-value-${idx}`;
    markTemplatable(valInp);

    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'btn btn-outline-danger btn-sm';
    rm.textContent = '✕';
    if (prefix) rm.dataset.wwField = `${prefix}-remove-${idx}`;
    rm.onclick = () => {
      const next = { ...assign };
      delete next[k];
      callUpdate(next, true);
      touch?.();
      // keep this block correct even if outer chooses not to hardRender
      renderAssignments(container, next, onUpdateAssign, touch, opts);
    };

    row.appendChild(ui.labeledNode('var', keyInp));
    row.appendChild(ui.labeledNode('value', valInp));
    row.appendChild(rm);
    wrap.appendChild(row);
  });

  const addBtn = document.createElement('button');
  addBtn.type = 'button';
  addBtn.className = 'btn btn-outline-secondary btn-sm';
  addBtn.textContent = 'Add assignment';
  if (prefix) addBtn.dataset.wwField = `${prefix}-add`;
  addBtn.onclick = () => {
    const next = { ...assign };
    const k = nextFreeKey(next);
    next[k] = 'value';
    callUpdate(next, true);
    touch?.();
    renderAssignments(container, next, onUpdateAssign, touch, opts);
  };

  wrap.appendChild(addBtn);
  container.appendChild(wrap);
}
