// Registry for executors + small UI helper toolkit (shared look & feel).

const _registry = new Map();

/** Register an executor by type. */
export function register(type, impl) {
  if (!type || typeof type !== 'string') throw new Error('executor type required');
  if (!impl || typeof impl.renderParams !== 'function') {
    throw new Error(`executor "${type}" must provide renderParams(container, step, ctx)`);
  }
  // normalize optional helpers
  const norm = {
    getDefaultParams: () => ({}),
    hints: () => [],                  // new: per-type variable hints (relative to ctx.steps.step_X)
    validate: () => [],
    ...impl,
  };
  _registry.set(type, norm);
}

/** Get an executor by type. */
export function get(type) {
  return _registry.get(type);
}

/** List registered types in stable order. */
export function getTypes() {
  return Array.from(_registry.keys());
}

/** Step-aware hints for the var panel (returns array of relative keys like 'outputs.webhook.status'). */
export function getHintsForStep(step) {
  const exec = _registry.get(step?.type);
  if (!exec) return [];
  try {
    const rel = exec.hints?.(step) ?? [];
    // Always add the common, executor-agnostic fields at the top:
    const common = ['status', 'ok', 'error', 'outputs'];
    // Merge (dedupe, preserve order: common first, then type-specific)
    const seen = new Set();
    const out = [];
    [...common, ...rel].forEach(k => {
      const key = String(k || '').trim();
      if (!key || seen.has(key)) return;
      seen.add(key);
      out.push(key);
    });
    return out;
  } catch {
    return ['status', 'ok', 'error', 'outputs'];
  }
}

/** ------- Shared UI helpers (consistent layout/labels/spacing) ------- */

function labeledNode(label, node) {
  const lbl = document.createElement('label');
  lbl.className = 'form-label small d-block';
  lbl.textContent = `${label}: `;
  lbl.appendChild(node);
  return lbl;
}
function input({ type='text', value='', onInput }) {
  const el = document.createElement('input');
  el.className = 'form-control form-control-sm';
  el.type = type;
  el.value = value ?? '';
  el.oninput = () => onInput?.(el.value);
  return el;
}
function textarea({ rows=4, value='', onInput }) {
  const el = document.createElement('textarea');
  el.className = 'form-control form-control-sm';
  el.rows = rows;
  el.value = value ?? '';
  el.oninput = () => onInput?.(el.value);
  return el;
}
function select({ options=[], value='', onChange }) {
  const el = document.createElement('select');
  el.className = 'form-select form-select-sm';
  options.forEach(o => el.add(new Option(o.label ?? o, o.value ?? o)));
  el.value = value ?? '';
  el.onchange = () => onChange?.(el.value);
  return el;
}
function row() {
  const r = document.createElement('div');
  r.className = 'row g-2';
  return r;
}
function col(node, w='col-md-6') {
  const c = document.createElement('div');
  c.className = w;
  c.appendChild(node);
  return c;
}
function radio(name, text, checked, onChange) {
  const id = `${name}-${Math.random().toString(36).slice(2,8)}`;
  const wrap = document.createElement('div'); wrap.className = 'form-check form-check-inline';
  const inputEl = document.createElement('input');
  inputEl.className = 'form-check-input';
  inputEl.type = 'radio';
  inputEl.name = name;
  inputEl.id = id;
  inputEl.checked = !!checked;
  inputEl.onchange = onChange;

  const label = document.createElement('label');
  label.className = 'form-check-label';
  label.htmlFor = id;
  label.textContent = text;

  wrap.appendChild(inputEl);
  wrap.appendChild(label);
  return { wrap, input: inputEl };
}

/** Export helpers for executors */
export const ui = {
  labeledNode, input, textarea, select, row, col, radio,
};
