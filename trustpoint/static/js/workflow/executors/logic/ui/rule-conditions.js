// static/js/workflow/executors/logic/ui/rule-conditions.js
import { ui } from '../../index.js';
import { newPredicate } from '../model.js';
import { renderOperand } from './operand.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

function normalizeModeStrict(raw) {
  const m = String(raw || '').trim().toLowerCase();
  return (m === 'or') ? 'or' : 'and';
}

function needsRightOperand(op) {
  const o = String(op || '').trim().toLowerCase();
  return ['eq', 'ne', 'lt', 'lte', 'gt', 'gte'].includes(o);
}

export function renderConditions(card, { ruleId, mode, predicates, catalogItems, getLiveRule, updateRule }) {
  const snapPreds = ensureArray(predicates);

  // Wrap all conditions for this rule so they read as one group.
  const group = document.createElement('div');
  group.className = 'lg-conds-group';
  group.dataset.wwField = `logic-rule-${ruleId}-conds-group`;

  // Tiny help text (explains AND/OR semantics)
  group.appendChild(
    ui.help(`All conditions are combined with ${normalizeModeStrict(mode).toUpperCase()}.`),
  );

  const conds = document.createElement('div');
  conds.className = 'lg-conds';
  conds.dataset.wwField = `logic-rule-${ruleId}-conds`;
  group.appendChild(conds);

  const joinWord = normalizeModeStrict(mode) === 'or' ? 'OR' : 'AND';

  const getLive = () => ensureObj(getLiveRule?.());
  const getLiveUI = () => ensureObj(getLive().ui);
  const getLivePreds = () => ensureArray(getLiveUI().predicates);

  const findPredIndexById = (predId) => {
    const livePreds = getLivePreds();
    return livePreds.findIndex((p) => String(ensureObj(p)._id || '') === String(predId || ''));
  };

  // Render each condition as a connected list item (joined by AND/OR pill)
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

        await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(mode), predicates: nextPreds } }, { structural });
      },
      catalogItems,
      { fieldPrefix: `logic-rule-${ruleId}-pred-${predId}-left` },
    );

    const opSel = ui.select({
      options: [
        { label: 'equals', value: 'eq' },
        { label: 'not equals', value: 'ne' },
        { label: 'greater than', value: 'gt' },
        { label: 'greater or equal', value: 'gte' },
        { label: 'less than', value: 'lt' },
        { label: 'less or equal', value: 'lte' },
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

        if (!needsRightOperand(v)) {
          delete next.right;
        } else if (!('right' in next)) {
          next.right = '';
        }

        const nextPreds = livePreds.slice();
        nextPreds[i] = next;

        await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(mode), predicates: nextPreds } }, { structural: true });
      },
    });
    opSel.dataset.wwField = `logic-rule-${ruleId}-pred-${predId}-op`;

    const opBox = document.createElement('div');
    opBox.appendChild(ui.labeledNode('Operator', opSel));

    const needsRight = needsRightOperand(ensureObj(predSnap).op || 'eq');
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

          await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(mode), predicates: nextPreds } }, { structural });
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

    // Actions row (remove condition)
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
      await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(mode), predicates: ensured } }, { structural: true });
    };

    condActions.appendChild(spacer);
    condActions.appendChild(rmPred);

    cond.appendChild(grid);
    cond.appendChild(condActions);
    conds.appendChild(cond);
  });

  // Add condition button INSIDE the list (at the end)
  const addRow = document.createElement('div');
  addRow.className = 'lg-conds-footer';
  addRow.dataset.wwField = `logic-rule-${ruleId}-conds-footer`;

  const addBtn = document.createElement('button');
  addBtn.type = 'button';
  addBtn.className = 'btn btn-outline-secondary btn-sm';
  addBtn.textContent = 'Add condition';
  addBtn.dataset.wwField = `logic-rule-${ruleId}-add-cond-inline`;
  addBtn.onclick = async () => {
    const live = getLive();
    const liveUI = ensureObj(live.ui);
    const livePreds = ensureArray(liveUI.predicates);
    const nextPreds = [...livePreds, newPredicate()];
    await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(mode), predicates: nextPreds } }, { structural: true });
  };

  addRow.appendChild(addBtn);
  conds.appendChild(addRow);

  card.appendChild(group);
}
