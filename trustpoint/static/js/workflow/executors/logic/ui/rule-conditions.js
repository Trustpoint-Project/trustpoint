// static/js/workflow/executors/logic/ui/rule-conditions.js
import { ui } from '../../index.js';
import { newPredicate } from '../model.js';
import { renderOperand } from './operand.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

export function renderConditions(card, { idx, rule, mode, predicates, catalogItems, getLiveRule, updateRule }) {
  const snapRule = ensureObj(rule);
  const snapUI = ensureObj(snapRule.ui);
  const snapPreds = ensureArray(predicates);

  const conds = document.createElement('div');
  conds.className = 'lg-conds';
  conds.dataset.wwField = `logic-rule-${idx}-conds`;

  const joinWord = mode === 'any' ? 'OR' : 'AND';

  snapPreds.forEach((pred, pidx) => {
    if (pidx > 0) {
      const join = document.createElement('div');
      join.className = 'lg-join-pill';
      join.textContent = joinWord;
      conds.appendChild(join);
    }

    const snapP = ensureObj(pred);

    const cond = document.createElement('div');
    cond.className = 'lg-cond';
    cond.dataset.wwField = `logic-rule-${idx}-pred-${pidx}`;

    const grid = document.createElement('div');
    grid.className = 'lg-cond-grid';

    const leftBox = document.createElement('div');
    leftBox.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-left`;

    renderOperand(
      leftBox,
      snapP.left ?? { path: 'ctx.vars.' },
      async (v, { structural = false } = {}) => {
        const live = ensureObj(getLiveRule?.());
        const liveUI = ensureObj(live.ui);
        const livePreds = ensureArray(liveUI.predicates);
        const basePred = ensureObj(livePreds[pidx] || snapP);

        const nextPreds = livePreds.slice();
        nextPreds[pidx] = { ...basePred, left: v };

        await updateRule({ ui: { ...liveUI, mode, predicates: nextPreds } }, { structural });
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
      value: String(snapP.op || 'eq'),
      onChange: async (v) => {
        const live = ensureObj(getLiveRule?.());
        const liveUI = ensureObj(live.ui);
        const livePreds = ensureArray(liveUI.predicates);
        const basePred = ensureObj(livePreds[pidx] || snapP);

        const next = { ...basePred, op: v };

        if (!['eq', 'ne'].includes(String(v))) {
          delete next.right;
        } else if (!('right' in next)) {
          next.right = '';
        }

        const nextPreds = livePreds.slice();
        nextPreds[pidx] = next;

        await updateRule({ ui: { ...liveUI, mode, predicates: nextPreds } }, { structural: true });
      },
    });
    opSel.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-op`;

    const opBox = document.createElement('div');
    opBox.appendChild(ui.labeledNode('Operator', opSel));

    const needsRight = ['eq', 'ne'].includes(String(snapP.op || 'eq'));
    const rightBox = document.createElement('div');
    rightBox.dataset.wwField = `logic-rule-${idx}-pred-${pidx}-right`;

    if (needsRight) {
      renderOperand(
        rightBox,
        snapP.right,
        async (v, { structural = false } = {}) => {
          const live = ensureObj(getLiveRule?.());
          const liveUI = ensureObj(live.ui);
          const livePreds = ensureArray(liveUI.predicates);
          const basePred = ensureObj(livePreds[pidx] || snapP);

          const nextPreds = livePreds.slice();
          nextPreds[pidx] = { ...basePred, right: v };

          await updateRule({ ui: { ...liveUI, mode, predicates: nextPreds } }, { structural });
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

    // Disable based on LIVE count (best effort); fallback to snapshot count.
    const liveCount = (() => {
      const live = ensureObj(getLiveRule?.());
      const liveUI = ensureObj(live.ui);
      return ensureArray(liveUI.predicates).length || snapPreds.length;
    })();

    rmPred.disabled = liveCount <= 1;
    rmPred.style.display = liveCount <= 1 ? 'none' : '';
    rmPred.onclick = async () => {
      const live = ensureObj(getLiveRule?.());
      const liveUI = ensureObj(live.ui);
      const livePreds = ensureArray(liveUI.predicates);

      const nextPreds = livePreds.slice();
      nextPreds.splice(pidx, 1);
      const ensured = nextPreds.length ? nextPreds : [newPredicate()];

      await updateRule({ ui: { ...liveUI, mode, predicates: ensured } }, { structural: true });
    };

    condActions.appendChild(spacer);
    condActions.appendChild(rmPred);

    cond.appendChild(grid);
    cond.appendChild(condActions);
    conds.appendChild(cond);
  });

  card.appendChild(conds);
}
