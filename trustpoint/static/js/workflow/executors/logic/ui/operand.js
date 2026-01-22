// static/js/workflow/executors/logic/ui/operand.js
import { ui } from '../../index.js';
import { markTemplatable } from '../../../template-fields.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }

function normalizeOperandKind(operand) {
  const isPath = operand && typeof operand === 'object' && !Array.isArray(operand) && typeof operand.path === 'string';
  return isPath ? 'path' : 'const';
}

function convertConstValue(fromValue, toType) {
  if (toType === 'null') return null;
  if (toType === 'string') return fromValue == null ? '' : String(fromValue);
  if (toType === 'number') {
    const n = Number(fromValue);
    return Number.isFinite(n) ? n : 0;
  }
  if (toType === 'boolean') {
    if (typeof fromValue === 'boolean') return fromValue;
    const s = String(fromValue || '').trim().toLowerCase();
    return s === 'true' || s === '1' || s === 'yes';
  }
  return fromValue;
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
      if (v === 'path') await onUpdate({ path: 'ctx.vars.' }, { structural: true });
      else await onUpdate('', { structural: true });
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
      // raw insertion for Logic operand paths
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
    const currentType =
      operand === null ? 'null'
        : typeof operand === 'boolean' ? 'boolean'
          : typeof operand === 'number' ? 'number'
            : 'string';

    const typeSel = ui.select({
      options: [
        { label: 'string', value: 'string' },
        { label: 'number', value: 'number' },
        { label: 'boolean', value: 'boolean' },
        { label: 'null', value: 'null' },
      ],
      value: currentType,
      onChange: async (t) => {
        const nextVal = convertConstValue(operand, t);
        await onUpdate(nextVal, { structural: true });
      },
    });
    if (prefix) typeSel.dataset.wwField = `${prefix}-const-type`;

    const valInp = ui.input({
      type: 'text',
      value: operand == null ? '' : String(operand),
      onInput: async (v) => {
        const t = typeSel.value;
        if (t === 'null') { await onUpdate(null, { structural: false }); return; }
        if (t === 'boolean') { await onUpdate(convertConstValue(v, 'boolean'), { structural: false }); return; }
        if (t === 'number') { await onUpdate(convertConstValue(v, 'number'), { structural: false }); return; }
        await onUpdate(String(v ?? ''), { structural: false });
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
