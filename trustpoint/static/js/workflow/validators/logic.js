// trustpoint/static/js/workflow/validators/logic.js
// Client-side validation for Logic step params (mirrors server rules + blocks invalid numeric constants).

import { state } from '../state.js';

const SEGMENT_CHARS = new Set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'.split(''));

function isDotPath(s) {
  if (typeof s !== 'string' || !s) return false;
  for (const ch of s) if (!SEGMENT_CHARS.has(ch)) return false;

  const parts = s.split('.');
  return parts.every(
    (p) => p && /[A-Za-z_]/.test(p[0]) && /^[A-Za-z0-9]+$/.test(p.replaceAll('_', ''))
  );
}

function isBareVarPath(s) {
  if (!isDotPath(s)) return false;
  const t = String(s).trim();
  if (t.startsWith('vars.')) return false;
  if (t.startsWith('ctx.')) return false;
  return true;
}

function isPlainObject(v) {
  return (v && typeof v === 'object' && !Array.isArray(v));
}

const ALLOWED_OPS = new Set([
  'eq', 'ne', 'lt', 'lte', 'gt', 'gte',
  'and', 'or', 'not', 'exists', 'truthy', 'falsy',
  'add', 'sub', 'mul', 'div', 'mod',
]);

function push(errors, msg) {
  errors.push(msg);
}

function getStableStepIds() {
  const steps = Array.isArray(state.steps) ? state.steps : [];
  return steps.map((_, i) => `step-${i + 1}`);
}

function isNumericString(s) {
  if (typeof s !== 'string') return false;
  const t = s.trim();
  if (t === '') return false;
  const n = Number(t);
  return Number.isFinite(n);
}

function validateConstObject({ idx, label, obj, errors }) {
  // Supports UI form: { const: ..., _ui_type: ... }
  const uiType = String(obj._ui_type || '').trim().toLowerCase();

  if (!('const' in obj)) {
    push(errors, `Step #${idx} (Logic): ${label} const object is missing "const".`);
    return;
  }

  const v = obj.const;

  if (uiType === 'number') {
    // Strict rule to prevent silent corruption:
    // - Accept finite number OR numeric string.
    // - Reject everything else (including empty string).
    if (typeof v === 'number' && Number.isFinite(v)) return;
    if (typeof v === 'string' && isNumericString(v)) return;

    push(errors, `Step #${idx} (Logic): ${label} constant is marked as number but is not a valid number.`);
    return;
  }

  if (uiType === 'null') {
    if (v !== null) {
      push(errors, `Step #${idx} (Logic): ${label} constant is marked as null but is not null.`);
    }
    return;
  }

  if (uiType === 'boolean') {
    // Accept boolean; allow strings during typing but do not fail hard here unless you want strictness.
    // If you want strict: require typeof v === 'boolean'
    return;
  }

  // string or unknown: always acceptable
}

function validateThen({ idx, label, thenObj, errors, currentStableId }) {
  if (!thenObj || typeof thenObj !== 'object' || Array.isArray(thenObj)) {
    push(errors, `Step #${idx} (Logic): ${label} then is required and must be an object.`);
    return;
  }

  let keys = 0;
  if (thenObj.pass === true) keys += 1;
  if ('goto' in thenObj) keys += 1;
  if ('stop' in thenObj) keys += 1;

  if (keys !== 1) {
    push(errors, `Step #${idx} (Logic): ${label} then must specify exactly one of pass/goto/stop.`);
    return;
  }

  if (thenObj.pass === true) return;

  if ('goto' in thenObj) {
    const tgt = String(thenObj.goto || '').trim();
    if (!tgt) {
      push(errors, `Step #${idx} (Logic): ${label} goto must be a non-empty step id.`);
      return;
    }

    const ids = getStableStepIds();
    if (!ids.includes(tgt)) {
      push(errors, `Step #${idx} (Logic): ${label} goto target "${tgt}" does not match any step id.`);
      return;
    }

    const curIndex = ids.indexOf(currentStableId);
    const tgtIndex = ids.indexOf(tgt);
    if (curIndex >= 0 && tgtIndex >= 0 && tgtIndex <= curIndex) {
      push(errors, `Step #${idx} (Logic): ${label} goto target "${tgt}" must refer to a later step (forward-only).`);
    }
    return;
  }

  const stopCfg = thenObj.stop;
  if (stopCfg === true) return;
  if (stopCfg && typeof stopCfg === 'object' && !Array.isArray(stopCfg)) {
    if ('reason' in stopCfg && stopCfg.reason != null && typeof stopCfg.reason !== 'string') {
      push(errors, `Step #${idx} (Logic): ${label} stop.reason must be a string if provided.`);
    }
    return;
  }

  push(errors, `Step #${idx} (Logic): ${label} stop must be true or an object.`);
}

function validateExpr({ idx, label, expr, errors }) {
  if (expr == null) return;

  // primitives + lists are allowed as literals (matches server)
  const t = typeof expr;
  if (t === 'string' || t === 'number' || t === 'boolean') return;
  if (Array.isArray(expr)) return;

  if (!expr || typeof expr !== 'object') {
    push(errors, `Step #${idx} (Logic): ${label} expression must be an object or primitive.`);
    return;
  }

  // {"path": "..."}
  if ('path' in expr) {
    const p = expr.path;
    if (typeof p !== 'string' || !p.trim()) {
      push(errors, `Step #${idx} (Logic): ${label} path must be a non-empty string.`);
    }
    return;
  }

  // {"const": ...} (UI may include _ui_type metadata)
  if ('const' in expr) {
    if (isPlainObject(expr)) {
      validateConstObject({ idx, label, obj: expr, errors });
    }
    return;
  }

  const op = String(expr.op || '').trim().toLowerCase();
  if (!ALLOWED_OPS.has(op)) {
    push(errors, `Step #${idx} (Logic): ${label} has unknown op "${op}".`);
    return;
  }

  if (op === 'and' || op === 'or') {
    const args = expr.args;
    if (!Array.isArray(args) || args.length === 0) {
      push(errors, `Step #${idx} (Logic): ${label} ${op} requires a non-empty args array.`);
      return;
    }
    args.forEach((a, i) => {
      validateExpr({ idx, label: `${label}.${op}[${i + 1}]`, expr: a, errors });
    });
    return;
  }

  if (op === 'not' || op === 'exists' || op === 'truthy' || op === 'falsy') {
    validateExpr({ idx, label: `${label}.${op}`, expr: expr.arg, errors });
    return;
  }

  if (op === 'add' || op === 'sub' || op === 'mul' || op === 'div' || op === 'mod') {
    const args = expr.args;
    if (Array.isArray(args)) {
      if (args.length < 2) {
        push(errors, `Step #${idx} (Logic): ${label} ${op} requires args with at least 2 items.`);
        return;
      }
      args.forEach((a, i) => {
        validateExpr({ idx, label: `${label}.${op}[${i + 1}]`, expr: a, errors });
      });
      return;
    }

    // Defensive/legacy: allow left/right
    validateExpr({ idx, label: `${label}.${op}.left`, expr: expr.left, errors });
    validateExpr({ idx, label: `${label}.${op}.right`, expr: expr.right, errors });
    return;
  }

  // binary comparison ops: eq/ne/lt/lte/gt/gte
  if (!('left' in expr)) {
    push(errors, `Step #${idx} (Logic): ${label}.${op} is missing "left".`);
    return;
  }
  if (!('right' in expr)) {
    push(errors, `Step #${idx} (Logic): ${label}.${op} is missing "right".`);
    return;
  }

  validateExpr({ idx, label: `${label}.${op}.left`, expr: expr.left, errors });
  validateExpr({ idx, label: `${label}.${op}.right`, expr: expr.right, errors });
}

function validateActions({ idx, label, actions, errors }) {
  if (actions == null) return;
  if (!Array.isArray(actions)) {
    push(errors, `Step #${idx} (Logic): ${label} actions must be an array.`);
    return;
  }

  actions.forEach((act, k0) => {
    const k = k0 + 1;
    if (!act || typeof act !== 'object' || Array.isArray(act)) {
      push(errors, `Step #${idx} (Logic): ${label} action #${k} must be an object.`);
      return;
    }

    const type = String(act.type || '').trim().toLowerCase();
    if (type !== 'set') {
      push(errors, `Step #${idx} (Logic): ${label} action #${k} has unknown type "${type}".`);
      return;
    }

    const assign = act.assign;
    if (!assign || typeof assign !== 'object' || Array.isArray(assign)) {
      push(errors, `Step #${idx} (Logic): ${label} action #${k} set.assign must be an object.`);
      return;
    }

    Object.entries(assign).forEach(([rawKey, rawVal]) => {
      const key = String(rawKey || '').trim();
      if (!key || !isBareVarPath(key)) {
        push(
          errors,
          `Step #${idx} (Logic): ${label} action #${k} set.assign key "${key}" must be a variable path like "serial_number" or "http.status" (no "vars." prefix).`
        );
        return;
      }
      validateExpr({ idx, label: `${label} action #${k} assign ${key}`, expr: rawVal, errors });
    });
  });
}

function validateWhen({ idx, label, when, errors }) {
  if (Array.isArray(when)) {
    if (when.length === 0) {
      push(errors, `Step #${idx} (Logic): ${label} must not be an empty array.`);
      return;
    }
    when.forEach((e, i) => {
      validateExpr({ idx, label: `${label}[${i + 1}]`, expr: e, errors });
    });
    return;
  }

  validateExpr({ idx, label, expr: when, errors });
}

export function validateLogic(step, idx, errors) {
  const params = (step && step.params && typeof step.params === 'object' && !Array.isArray(step.params))
    ? step.params
    : {};

  const currentStableId = `step-${idx}`;

  const def = params.default;
  if (!def || typeof def !== 'object' || Array.isArray(def)) {
    push(errors, `Step #${idx} (Logic): default is required and must be an object.`);
  }

  let rules = params.rules;
  if (rules == null) rules = [];
  if (!Array.isArray(rules)) {
    push(errors, `Step #${idx} (Logic): rules must be an array if provided.`);
    return;
  }

  rules.forEach((rule, j0) => {
    const j = j0 + 1;

    if (!rule || typeof rule !== 'object' || Array.isArray(rule)) {
      push(errors, `Step #${idx} (Logic): rule #${j} must be an object.`);
      return;
    }

    const when = rule.when;
    if (when == null) {
      push(errors, `Step #${idx} (Logic): rule #${j} is missing "when".`);
    } else {
      validateWhen({ idx, label: `rule #${j} when`, when, errors });
    }

    validateActions({ idx, label: `rule #${j}`, actions: rule.actions, errors });
    validateThen({
      idx,
      label: `rule #${j}`,
      thenObj: rule.then,
      errors,
      currentStableId,
    });
  });

  if (def && typeof def === 'object' && !Array.isArray(def)) {
    validateActions({ idx, label: 'default', actions: def.actions, errors });
    validateThen({
      idx,
      label: 'default',
      thenObj: def.then,
      errors,
      currentStableId,
    });
  }
}
