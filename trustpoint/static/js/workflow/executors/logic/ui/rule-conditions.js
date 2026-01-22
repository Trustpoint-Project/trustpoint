// static/js/workflow/executors/logic/ui/rule-conditions.js
import { ui } from '../../index.js';
import { newPredicate } from '../model.js';
import { renderOperand } from './operand.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }

export function renderConditions(card, { idx, rule, mode, predicates, catalogItems, updateRule }) {
  const r = ensureObj(rule);
  const uiCond = ensureObj(r.ui);

  const conds = document.createElement('div');
  conds.className = 'lg-conds';
  conds.dataset.wwField = `logic-rule-${idx}-conds`;

  const joinWord = mode === 'any' ? 'OR' : 'AND';

  predicates.forEach((pred, pidx) => {
    if (pidx > 0) {
      const join = document.createElement('div');
      join.className = 'lg-join-pill';
      join.textContent = joinWord;
      conds.appendChild(join);
    }

    const p = ensureObj(pred);

    const cond = document.createElement('div');
    cond.className = 'lg-cond';
    cond.dataset.wwField = `logic-rule-${idx}-pred-${pidx}`;

    const grid = document.createElement('div');
    grid.className = 'lg-cond-grid';

    const leftBox = document.createElement('div');
    leftBox.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-left`;
    renderOperand(
      leftBox,
      p.left ?? { path: 'ctx.vars.' },
      async (v, { structural = false } = {}) => {
        const nextPreds = predicates.slice();
        nextPreds[pidx] = { ...p, left: v };
        await updateRule({ ...r, ui: { ...uiCond, mode, predicates: nextPreds } }, { structural });
      },
      catalogItems,
      { fieldPrefix: `logic-rule-${idx}-pred-${pidx}-left` },
    );

    const opSel = ui.select({
      options: [
        { label: 'equals', value: 'eq' },
        { label: 'not equals', value: 'ne' },
        { label: 'exists', value: 'exists' },
        { label: 'is truthy', value: 'truthy' },
        { label: 'is falsy', value: 'falsy' },
      ],
      value: String(p.op || 'eq'),
      onChange: async (v) => {
        const nextPreds = predicates.slice();
        const next = { ...p, op: v };

        if (!['eq', 'ne'].includes(String(v))) {
          delete next.right;
        } else if (!('right' in next)) {
          next.right = '';
        }

        nextPreds[pidx] = next;
        await updateRule({ ...r, ui: { ...uiCond, mode, predicates: nextPreds } }, { structural: true });
      },
    });
    opSel.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-op`;

    const opBox = document.createElement('div');
    opBox.appendChild(ui.labeledNode('Operator', opSel));

    const needsRight = ['eq', 'ne'].includes(String(p.op || 'eq'));
    const rightBox = document.createElement('div');
    rightBox.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-right`;

    if (needsRight) {
      renderOperand(
        rightBox,
        p.right,
        async (v, { structural = false } = {}) => {
          const nextPreds = predicates.slice();
          nextPreds[pidx] = { ...p, right: v };
          await updateRule({ ...r, ui: { ...uiCond, mode, predicates: nextPreds } }, { structural });
        },
        catalogItems,
        { fieldPrefix: `logic-rule-${idx}-pred-${pidx}-right` },
      );
    } else {
      rightBox.appendChild(ui.help(''));
    }

    grid.appendChild(leftBox);
    grid.appendChild(opBox);
    grid.appendChild(rightBox);

    const condActions = document.createElement('div');
    condActions.className = 'lg-cond-actions';

    const spacer = document.createElement('div');
    spacer.className = 'lg-subtle';
    spacer.textContent = '';

    const rmPred = document.createElement('button');
    rmPred.type = 'button';
    rmPred.className = 'btn btn-outline-danger btn-sm';
    rmPred.textContent = 'Remove condition';
    rmPred.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-remove`;
    rmPred.disabled = predicates.length <= 1;
    rmPred.style.display = predicates.length <= 1 ? 'none' : '';
    rmPred.onclick = async () => {
      const nextPreds = predicates.slice();
      nextPreds.splice(pidx, 1);
      const ensured = nextPreds.length ? nextPreds : [newPredicate()];
      await updateRule({ ...r, ui: { ...uiCond, mode, predicates: ensured } }, { structural: true });
    };

    condActions.appendChild(spacer);
    condActions.appendChild(rmPred);

    cond.appendChild(grid);
    cond.appendChild(condActions);
    conds.appendChild(cond);
  });

  card.appendChild(conds);
}
