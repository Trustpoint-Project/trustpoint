// static/js/workflow/executors/logic/model.js
function ensureArray(v) { return Array.isArray(v) ? v : []; }
function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }

export function newPredicate() {
  return { left: { path: 'ctx.vars.' }, op: 'eq', right: '' };
}

export function newRule() {
  return {
    ui: { mode: 'all', predicates: [newPredicate()] },
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
  return (String(mode) === 'any') ? { op: 'or', args: preds } : { op: 'and', args: preds };
}

export function ruleToBackend(rule) {
  const r = ensureObj(rule);
  const uiPart = ensureObj(r.ui);
  const when = buildWhenExpr(uiPart.mode, ensureArray(uiPart.predicates));
  const assign = ensureObj(r.assign);

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

  // Extract assign from first set-action if present, otherwise {}
  const a0 = ensureArray(d.actions)[0];
  const assign = (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set')
    ? ensureObj(a0.assign)
    : {};

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

  // normalize default.actions/default.then
  if (!Array.isArray(p.default.actions)) p.default.actions = [];
  if (!p.default.then || typeof p.default.then !== 'object') p.default.then = { pass: true };

  return p;
}

/**
 * Enforce:
 * - at least 1 rule
 * - each rule has at least 1 predicate
 */
export function ensureMinRulesAndConds(uiRules) {
  const rules = ensureArray(uiRules).map((r) => {
    const rr = ensureObj(r);
    const ui = ensureObj(rr.ui);
    const preds = ensureArray(ui.predicates);
    if (!preds.length) ui.predicates = [newPredicate()];
    rr.ui = ui;
    return rr;
  });

  if (!rules.length) return [newRule()];
  return rules;
}
