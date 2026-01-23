// static/js/workflow/executors/logic/model.js
function ensureArray(v) { return Array.isArray(v) ? v : []; }
function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }

function uid() {
  // Stable enough for UI identity; crypto.randomUUID preferred.
  try {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
      return crypto.randomUUID();
    }
  } catch {}
  return `id_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeModeStrict(raw) {
  // Only accept 'and' or 'or'. Anything else becomes 'and'.
  const m = String(raw || '').trim().toLowerCase();
  return (m === 'or') ? 'or' : 'and';
}

export function newPredicate() {
  return { _id: uid(), left: { path: 'ctx.vars.' }, op: 'eq', right: '' };
}

export function newRule() {
  return {
    _id: uid(),
    ui: { mode: 'and', predicates: [newPredicate()] },
    assign: {},
    then: { pass: true },
  };
}

function buildPredicateExpr(pred) {
  const p = ensureObj(pred);
  const op = String(p.op || 'eq');

  const left = p.left ?? { path: 'ctx.vars.' };
  const right = p.right;

  if (op === 'exists') return { op: 'exists', arg: left };
  if (op === 'truthy') return { op: 'truthy', arg: left };
  if (op === 'falsy') return { op: 'falsy', arg: left };
  if (op === 'ne') return { op: 'ne', left, right };
  return { op: 'eq', left, right };
}

function buildWhenExpr(mode, predicates) {
  const preds = ensureArray(predicates).map(buildPredicateExpr).filter(Boolean);
  if (!preds.length) return { op: 'truthy', arg: { path: 'ctx.vars.' } };
  if (preds.length === 1) return preds[0];

  const m = normalizeModeStrict(mode);
  return (m === 'or') ? { op: 'or', args: preds } : { op: 'and', args: preds };
}

/**
 * Parse JSON-like strings only at backend conversion time.
 * Preserves template strings verbatim.
 */
function parseMaybeJSON(v) {
  if (typeof v !== 'string') return v;

  const s = v.trim();

  // Preserve templates verbatim
  if (s.includes('{{') || s.includes('}}')) return v;

  const c = s[0];
  const looksJson =
    c === '{' || c === '[' || c === '"' || c === '-' ||
    (c >= '0' && c <= '9') ||
    s === 'true' || s === 'false' || s === 'null';

  if (!looksJson) return v;

  try { return JSON.parse(s); } catch { return v; }
}

function normalizeAssignForBackend(assign) {
  const a = ensureObj(assign);
  const out = {};
  for (const [k, v] of Object.entries(a)) {
    out[k] = parseMaybeJSON(v);
  }
  return out;
}

export function ruleToBackend(rule) {
  const r = ensureObj(rule);
  const uiPart = ensureObj(r.ui);

  const when = buildWhenExpr(uiPart.mode, ensureArray(uiPart.predicates));

  const assignUi = ensureObj(r.assign);
  const assign = normalizeAssignForBackend(assignUi);

  const actions = [];
  if (Object.keys(assign).length) actions.push({ type: 'set', assign });

  return { when, actions, then: ensureObj(r.then) };
}

/**
 * Converts the UI "default" block to the backend shape.
 * Backend expects: { actions: [{type:'set', assign:{...}}], then: {...} }
 */
export function defaultToBackend(def) {
  const d = ensureObj(def);

  const a0 = ensureArray(d.actions)[0];
  const assignUi = (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set')
    ? ensureObj(a0.assign)
    : {};

  const assign = normalizeAssignForBackend(assignUi);

  return {
    actions: [{ type: 'set', assign }],
    then: ensureObj(d.then),
  };
}

export function ensureLogicDefaults(params) {
  const p = ensureObj(params);

  if (!Array.isArray(p._ui_rules)) p._ui_rules = [];
  if (!Array.isArray(p.rules)) p.rules = [];

  if (!p.default || typeof p.default !== 'object') p.default = { actions: [], then: { pass: true } };

  if (!Array.isArray(p.default.actions)) p.default.actions = [];
  if (!p.default.then || typeof p.default.then !== 'object') p.default.then = { pass: true };

  return p;
}

/**
 * Enforce:
 * - at least 1 rule
 * - each rule has stable _id
 * - each predicate has stable _id
 * - each rule has at least 1 predicate
 * - mode is strictly 'and' or 'or' (anything else becomes 'and')
 */
export function ensureMinRulesAndConds(uiRules) {
  const rules = ensureArray(uiRules).map((r) => {
    const rr = ensureObj(r);
    if (!rr._id) rr._id = uid();

    const ui = ensureObj(rr.ui);
    ui.mode = normalizeModeStrict(ui.mode);

    const preds0 = ensureArray(ui.predicates).map((p) => {
      const pp = ensureObj(p);
      if (!pp._id) pp._id = uid();
      return pp;
    });

    if (!preds0.length) ui.predicates = [newPredicate()];
    else ui.predicates = preds0;

    rr.ui = ui;
    return rr;
  });

  if (!rules.length) return [newRule()];
  return rules;
}
