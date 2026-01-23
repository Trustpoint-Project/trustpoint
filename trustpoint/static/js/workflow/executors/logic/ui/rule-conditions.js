// static/js/workflow/executors/logic/ui/rule-conditions.js
import { ui } from '../../index.js';
import { newPredicate } from '../model.js';
import { renderOperand } from './operand.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

export function renderConditions(card, { ruleId, mode, predicates, catalogItems, getLiveRule, updateRule }) {
  const snapPreds = ensureArray(predicates);

  const conds = document.createElement('div');
  conds.className = 'lg-conds';
  conds.dataset.wwField = `logic-rule-${ruleId}-conds`;

  const joinWord = mode === 'any' ? 'OR' : 'AND';

  const getLive = () => ensureObj(getLiveRule?.());
  const getLiveUI = () => ensureObj(getLive().ui);
  const getLivePreds = () => ensureArray(getLiveUI().predicates);

  const findPredIndexById = (predId) => {
    const livePreds = getLivePreds();
    return livePreds.findIndex((p) => String(ensureObj(p)._id || '') === String(predId || ''));
  };

  snapPreds.forEach((predSnap, pidxDisplay) => {
    const predId = String(ensureObj(predSnap)._id || '');

    if (pidxDisplay > 0) {
      const join = document.createElement('div');
      join.className = 'lg-join-pill';
      join.textContent = joinWord;
      conds.appendChild(join);
    }

    const cond = document.createElement('div');
    cond.className = 'lg-cond';
    cond.dataset.wwField = `logic-rule-${ruleId}-pred-${predId || pidxDisplay}`;

    const grid = document.createElement('div');
    grid.className = 'lg-cond-grid';

    const leftBox = document.createElement('div');
    leftBox.dataset.wwField = `logic-rule-${ruleId}-pred-${predId}-left`;

    renderOperand(
      leftBox,
      ensureObj(predSnap).left ?? { path: 'ctx.vars.' },
      async (v, { structural = false } = {}) => {
        const liveUI = getLiveUI();
        const livePreds = getLivePreds();
        const i = findPredIndexById(predId);
        if (i < 0) return;

        const base = ensureObj(livePreds[i]);
        const nextPreds = livePreds.slice();
        nextPreds[i] = { ...base, left: v };

        await updateRule({ ui: { ...liveUI, mode, predicates: nextPreds } }, { structural });
      },
      catalogItems,
      { fieldPrefix: `logic-rule-${ruleId}-pred-${predId}-left` },
    );

    const opSel = ui.select({
      options: [
        { label: 'equals', value: 'eq' },
        { label: 'not equals', value: 'ne' },
        { label: 'exists', value: 'exists' },
        { label: 'is truthy', value: 'truthy' },
        { label: 'is falsy', value: 'falsy' },
      ],
      value: String(ensureObj(predSnap).op || 'eq'),
      onChange: async (v) => {
        const liveUI = getLiveUI();
        const livePreds = getLivePreds();
        const i = findPredIndexById(predId);
        if (i < 0) return;

        const base = ensureObj(livePreds[i]);
        const next = { ...base, op: v };

        if (!['eq', 'ne'].includes(String(v))) {
          delete next.right;
        } else if (!('right' in next)) {
          next.right = '';
        }

        const nextPreds = livePreds.slice();
        nextPreds[i] = next;

        await updateRule({ ui: { ...liveUI, mode, predicates: nextPreds } }, { structural: true });
      },
    });
    opSel.dataset.wwField = `logic-rule-${ruleId}-pred-${predId}-op`;

    const opBox = document.createElement('div');
    opBox.appendChild(ui.labeledNode('Operator', opSel));

    const needsRight = ['eq', 'ne'].includes(String(ensureObj(predSnap).op || 'eq'));
    const rightBox = document.createElement('div');
    rightBox.dataset.wwField = `logic-rule-${ruleId}-pred-${predId}-right`;

    if (needsRight) {
      renderOperand(
        rightBox,
        ensureObj(predSnap).right,
        async (v, { structural = false } = {}) => {
          const liveUI = getLiveUI();
          const livePreds = getLivePreds();
          const i = findPredIndexById(predId);
          if (i < 0) return;

          const base = ensureObj(livePreds[i]);
          const nextPreds = livePreds.slice();
          nextPreds[i] = { ...base, right: v };

          await updateRule({ ui: { ...liveUI, mode, predicates: nextPreds } }, { structural });
        },
        catalogItems,
        { fieldPrefix: `logic-rule-${ruleId}-pred-${predId}-right` },
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
    rmPred.dataset.wwField = `logic-rule-${ruleId}-pred-${predId}-remove`;

    const liveCount = getLivePreds().length || snapPreds.length;
    rmPred.disabled = liveCount <= 1;
    rmPred.style.display = liveCount <= 1 ? 'none' : '';
    rmPred.onclick = async () => {
      const liveUI = getLiveUI();
      const livePreds = getLivePreds();
      const i = findPredIndexById(predId);
      if (i < 0) return;

      const nextPreds = livePreds.slice();
      nextPreds.splice(i, 1);

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
