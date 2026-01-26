// static/js/workflow/executors/logic/ui/operand.js
import { ui } from '../../index.js';
import { markTemplatable } from '../../../template-fields.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }
function isPlainObject(v) { return (v && typeof v === 'object' && !Array.isArray(v)); }

function normalizeOperandKind(operand) {
  if (isPlainObject(operand) && typeof operand.path === 'string') return 'path';
  return 'const';
}

function unwrapConst(operand) {
  // We support both:
  // - legacy primitives: "abc", 12, true, null
  // - object form: { const: ..., _ui_type: ... }
  if (isPlainObject(operand) && 'const' in operand) return operand.const;
  return operand;
}

function inferUiTypeFromValue(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return 'boolean';
  if (typeof v === 'number') return 'number';
  return 'string';
}

function getUiType(operand) {
  if (isPlainObject(operand) && typeof operand._ui_type === 'string') {
    const t = operand._ui_type;
    if (t === 'string' || t === 'number' || t === 'boolean' || t === 'null') return t;
  }
  return inferUiTypeFromValue(unwrapConst(operand));
}

function makeConstOperand(value, uiType) {
  // Keep raw value; do not coerce invalid numbers to 0.
  const t = (uiType === 'string' || uiType === 'number' || uiType === 'boolean' || uiType === 'null')
    ? uiType
    : inferUiTypeFromValue(value);

  return { const: value, _ui_type: t };
}

function normalizeConstForType(rawValue, uiType) {
  // IMPORTANT: Do not “fix” invalid values by replacing them with magic defaults.
  // Keep raw user input.
  if (uiType === 'null') return null;

  if (uiType === 'boolean') {
    if (typeof rawValue === 'boolean') return rawValue;
    const s = String(rawValue ?? '').trim().toLowerCase();
    if (s === 'true' || s === '1' || s === 'yes') return true;
    if (s === 'false' || s === '0' || s === 'no') return false;
    // keep raw if it is not clearly a boolean; validator should block save if needed
    return rawValue;
  }

  if (uiType === 'number') {
    // Keep as string while typing; validator will enforce numeric validity.
    // If it is already a number, keep it.
    if (typeof rawValue === 'number') return rawValue;
    return String(rawValue ?? '');
  }

  // string
  return rawValue == null ? '' : String(rawValue);
}

/**
 * IMPORTANT:
 * - onInput => SOFT update only (no structural re-render)
 * - kind/type changes => structural re-render (caller hardRender)
 */
export function renderOperand(container, operand, onUpdate, catalogItems, opts = {}) {
  container.textContent = '';

  const prefix = String(opts.fieldPrefix || '').trim();

  const kindSel = ui.select({
    options: [
      { label: 'variable (ctx.*)', value: 'path' },
      { label: 'constant', value: 'const' },
    ],
    value: normalizeOperandKind(operand),
    onChange: async (v) => {
      if (v === 'path') {
        await onUpdate({ path: 'ctx.vars.' }, { structural: true });
      } else {
        // default const operand: empty string
        await onUpdate(makeConstOperand('', 'string'), { structural: true });
      }
    },
  });
  if (prefix) kindSel.dataset.wwField = `${prefix}-kind`;

  const body = document.createElement('div');
  body.className = 'mt-2';

  if (kindSel.value === 'path') {
    const isPath = normalizeOperandKind(operand) === 'path';
    const curPath = isPath ? String(operand.path || '') : 'ctx.vars.';

    const selectable = ensureArray(catalogItems).filter((x) => x.path !== 'ctx.vars.*');
    const hasRealVars = selectable.some((x) => x.path.startsWith('ctx.vars.'));
    const hasWildcardOnly = ensureArray(catalogItems).some((x) => x.path === 'ctx.vars.*') && !hasRealVars;

    if (hasWildcardOnly) {
      const inp = ui.input({
        type: 'text',
        value: curPath.startsWith('ctx.vars.') ? curPath : 'ctx.vars.',
        onInput: async (v) => {
          await onUpdate({ path: String(v || '').trim() }, { structural: false });
        },
      });
      inp.dataset.tplMode = 'raw';
      if (prefix) inp.dataset.wwField = `${prefix}-path-input`;
      markTemplatable(inp);
      body.appendChild(ui.labeledNode('Path', inp));
    } else {
      const sel = document.createElement('select');
      sel.className = 'form-select form-select-sm';
      if (prefix) sel.dataset.wwField = `${prefix}-path-select`;

      const groups = new Map();
      selectable.forEach((it) => {
        const g = it.group || 'Variables';
        if (!groups.has(g)) groups.set(g, []);
        groups.get(g).push(it);
      });

      for (const [gname, arr] of groups.entries()) {
        const og = document.createElement('optgroup');
        og.label = gname;
        arr.forEach((it) => og.appendChild(new Option(it.label, it.path)));
        sel.appendChild(og);
      }

      if (curPath && !selectable.some((x) => x.path === curPath)) {
        sel.insertBefore(new Option(curPath, curPath), sel.firstChild);
      }

      sel.value = curPath || (selectable[0]?.path || 'ctx.vars.');
      sel.onchange = async () => {
        await onUpdate({ path: sel.value }, { structural: false });
      };

      body.appendChild(ui.labeledNode('Path', sel));
    }
  } else {
    const uiType = getUiType(operand);
    const curValue = unwrapConst(operand);

    const typeSel = ui.select({
      options: [
        { label: 'string', value: 'string' },
        { label: 'number', value: 'number' },
        { label: 'boolean', value: 'boolean' },
        { label: 'null', value: 'null' },
      ],
      value: uiType,
      onChange: async (t) => {
        // Convert representation without magic defaults.
        const nextRaw = normalizeConstForType(curValue, t);
        await onUpdate(makeConstOperand(nextRaw, t), { structural: true });
      },
    });
    if (prefix) typeSel.dataset.wwField = `${prefix}-const-type`;

    const valInp = ui.input({
      type: 'text',
      value: (uiType === 'null') ? '' : String(curValue ?? ''),
      onInput: async (v) => {
        const t = typeSel.value;

        if (t === 'null') {
          await onUpdate(makeConstOperand(null, 'null'), { structural: false });
          return;
        }

        if (t === 'boolean') {
          // Keep raw unless it is clearly a boolean token; validator can decide strictness.
          const next = normalizeConstForType(v, 'boolean');
          await onUpdate(makeConstOperand(next, 'boolean'), { structural: false });
          return;
        }

        if (t === 'number') {
          // Keep as string while typing; validator will block invalid on save.
          await onUpdate(makeConstOperand(String(v ?? ''), 'number'), { structural: false });
          return;
        }

        await onUpdate(makeConstOperand(String(v ?? ''), 'string'), { structural: false });
      },
    });
    if (prefix) valInp.dataset.wwField = `${prefix}-const-value`;
    markTemplatable(valInp);

    const line = document.createElement('div');
    line.className = 'lg-row';
    line.appendChild(typeSel);
    if (typeSel.value !== 'null') line.appendChild(valInp);

    body.appendChild(ui.labeledNode('Value', line));
  }

  container.appendChild(ui.labeledNode('Kind', kindSel));
  container.appendChild(body);
}
