// static/js/workflow/executors/logic/ui/assignments.js
import { ui } from '../../index.js';
import { markTemplatable } from '../../../template-fields.js';

function ensureObj(v) {
  return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {};
}

function nextFreeKey(assign, base = 'var') {
  const a = ensureObj(assign);
  if (!(base in a)) return base;

  for (let i = 1; i < 1000; i++) {
    const k = `${base}${i}`;
    if (!(k in a)) return k;
  }
  return `${base}${Date.now()}`;
}

/**
 * Preserve focus inside this container by data-ww-field during local rerenders.
 * Keeps caret position stable when the assignments block rebuilds.
 */
function preserveFocus(container, domWriteFn) {
  const active = (document.activeElement instanceof HTMLElement) ? document.activeElement : null;
  const key = active?.dataset?.wwField ? String(active.dataset.wwField) : null;

  let sel = null;
  if (active && (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement)) {
    try { sel = { start: active.selectionStart, end: active.selectionEnd }; } catch { sel = null; }
  }

  domWriteFn();

  if (!key) return;
  requestAnimationFrame(() => {
    const el = container.querySelector?.(`[data-ww-field="${CSS.escape(key)}"]`);
    if (!(el instanceof HTMLElement)) return;
    try { el.focus({ preventScroll: true }); } catch { try { el.focus(); } catch {} }
    if (sel && (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) {
      try { el.setSelectionRange(sel.start ?? 0, sel.end ?? 0); } catch {}
    }
  });
}

export function renderAssignments(container, assignObj, onUpdateAssign, touch, opts = {}) {
  container.textContent = '';

  const prefix = String(opts.fieldPrefix || '').trim();

  // Always read LIVE assign for mutations, never rely on render snapshot.
  const getLiveAssign = (typeof opts.getLiveAssign === 'function')
    ? opts.getLiveAssign
    : () => ensureObj(assignObj);

  const callUpdate = (next, structural = false) => {
    try { onUpdateAssign?.(next, { structural }); } catch { onUpdateAssign?.(next); }
  };

  const wrap = document.createElement('div');
  wrap.className = 'lg-card';
  if (prefix) wrap.dataset.wwField = `${prefix}-wrap`;

  wrap.appendChild(
    ui.help('Defines ctx.vars.* when this branch is true.'),
  );

  // Snapshot for display only
  const snapAssign = ensureObj(assignObj);
  const entries = Object.entries(snapAssign);

  if (!entries.length) wrap.appendChild(ui.help('No variables defined yet.'));

  /**
   * Commit a rename from oldKey -> newKey using LIVE state.
   * - Only called on blur or Enter (structural commit).
   * - Rebuilds this block after commit so value handlers bind to the new key.
   */
  const commitRename = (oldKey, rawNewKey) => {
    const nk0 = String(rawNewKey ?? '').trim();
    if (!nk0 || nk0 === oldKey) return;

    const live = ensureObj(getLiveAssign());
    const next = { ...live };

    if (!(oldKey in next)) return;

    let nk = nk0;

    // Resolve collisions deterministically
    if (nk in next) {
      nk = nextFreeKey(next, nk);
    }

    const oldVal = next[oldKey];
    delete next[oldKey];
    next[nk] = oldVal;

    callUpdate(next, true);
    touch?.();

    preserveFocus(container, () => {
      renderAssignments(container, next, onUpdateAssign, touch, opts);
    });
  };

  entries.forEach(([k, v], idx) => {
    const row = document.createElement('div');
    row.className = 'lg-row mb-2';
    if (prefix) row.dataset.wwField = `${prefix}-row-${idx}`;

    // Key editor: do NOT mutate state on every keystroke.
    // Keep the draft in the input; commit on blur/Enter only.
    const keyInp = ui.input({
      type: 'text',
      value: k,
      onInput: () => {
        // intentionally no state write here
      },
    });
    if (prefix) keyInp.dataset.wwField = `${prefix}-key-${idx}`;

    keyInp.onblur = () => {
      commitRename(k, keyInp.value);
    };
    keyInp.onkeydown = (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        commitRename(k, keyInp.value);

        // Move focus to value field for this row if present
        const valEl = row.querySelector?.(`[data-ww-field="${CSS.escape(`${prefix}-value-${idx}`)}"]`);
        if (valEl instanceof HTMLElement) {
          try { valEl.focus({ preventScroll: true }); } catch { try { valEl.focus(); } catch {} }
        }
      } else if (e.key === 'Escape') {
        e.preventDefault();
        keyInp.value = k;
        try { keyInp.blur(); } catch {}
      }
    };

    // Value editor: updates the current key (k) for this row.
    // After rename commit, the block rebuilds, so closures update.
    const valInp = ui.input({
      type: 'text',
      value: (v == null) ? '' : String(v),
      onInput: (raw) => {
        const live = ensureObj(getLiveAssign());
        const next = { ...live, [k]: String(raw ?? '') };
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
      const live = ensureObj(getLiveAssign());
      const next = { ...live };
      delete next[k];
      callUpdate(next, true);
      touch?.();
      preserveFocus(container, () => {
        renderAssignments(container, next, onUpdateAssign, touch, opts);
      });
    };

    row.appendChild(ui.labeledNode('name', keyInp));
    row.appendChild(ui.labeledNode('value', valInp));
    row.appendChild(rm);
    wrap.appendChild(row);
  });

  const addBtn = document.createElement('button');
  addBtn.type = 'button';
  addBtn.className = 'btn btn-outline-secondary btn-sm';
  addBtn.textContent = 'Define variable';
  if (prefix) addBtn.dataset.wwField = `${prefix}-add`;
  addBtn.onclick = () => {
    const live = ensureObj(getLiveAssign());
    const next = { ...live };
    const k = nextFreeKey(next, 'var');
    next[k] = '';
    callUpdate(next, true);
    touch?.();
    preserveFocus(container, () => {
      renderAssignments(container, next, onUpdateAssign, touch, opts);
    });
  };

  wrap.appendChild(addBtn);
  container.appendChild(wrap);
}
