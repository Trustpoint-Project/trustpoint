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

export function renderAssignments(container, assignObj, onUpdateAssign, touch) {
  container.textContent = '';
  const assign = ensureObj(assignObj);

  const wrap = document.createElement('div');
  wrap.className = 'lg-card';
  wrap.appendChild(ui.help('Assignments write to ctx.vars. Values may be JSON or {{ ctx.* }} templates.'));

  const entries = Object.entries(assign);
  if (!entries.length) wrap.appendChild(ui.help('No assignments yet.'));

  for (const [k, v] of entries) {
    const row = document.createElement('div');
    row.className = 'lg-row mb-2';

    const keyInp = ui.input({
      type: 'text',
      value: k,
      onInput: (newKey) => {
        const nk = String(newKey || '').trim();
        const next = { ...assign };
        const oldVal = next[k];
        delete next[k];
        if (nk) next[nk] = oldVal;
        onUpdateAssign(next);
        touch?.();
      },
    });

    const valInp = ui.input({
      type: 'text',
      value: JSON.stringify(v ?? null),
      onInput: (raw) => {
        let parsed;
        try { parsed = JSON.parse(raw); } catch { parsed = raw; }
        const next = { ...assign, [k]: parsed };
        onUpdateAssign(next);
        touch?.();
      },
    });
    markTemplatable(valInp);

    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'btn btn-outline-danger btn-sm';
    rm.textContent = '✕';
    rm.onclick = () => {
      const next = { ...assign };
      delete next[k];
      onUpdateAssign(next);
      touch?.();
      // structural change => re-render this block
      renderAssignments(container, next, onUpdateAssign, touch);
    };

    row.appendChild(ui.labeledNode('var', keyInp));
    row.appendChild(ui.labeledNode('value', valInp));
    row.appendChild(rm);
    wrap.appendChild(row);
  }

  const addBtn = document.createElement('button');
  addBtn.type = 'button';
  addBtn.className = 'btn btn-outline-secondary btn-sm';
  addBtn.textContent = 'Add assignment';
  addBtn.onclick = () => {
    const next = { ...assign };
    const k = nextFreeKey(next);
    next[k] = 'value';
    onUpdateAssign(next);
    touch?.();
    // structural change => re-render this block
    renderAssignments(container, next, onUpdateAssign, touch);
  };

  wrap.appendChild(addBtn);
  container.appendChild(wrap);
}
