// static/js/workflow/executors/logic/ui/rule-card.js
import { ui } from '../../index.js';
import { newPredicate } from '../model.js';
import { renderConditions } from './rule-conditions.js';
import { renderAssignments } from './assignments.js';
import { renderThen } from './then.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

export function renderRuleCard(container, { idx, rule, rulesCount, catalogItems, updateRule, removeRule, touch }) {
  container.textContent = '';

  const r = ensureObj(rule);
  const uiCond = ensureObj(r.ui);
  const predicates = ensureArray(uiCond.predicates);

  const card = document.createElement('div');
  card.className = 'lg-card';
  card.dataset.wwField = `logic-rule-${idx}`;

  const head = document.createElement('div');
  head.className = 'lg-rule-head';

  const leftHead = document.createElement('div');
  leftHead.className = 'd-flex align-items-center gap-2 flex-wrap';

  const tag = document.createElement('span');
  tag.className = 'lg-rule-tag';
  tag.textContent = idx === 0 ? 'IF' : 'ELSE IF';

  const title = document.createElement('strong');
  title.textContent = `Rule ${idx + 1}`;

  leftHead.appendChild(tag);
  leftHead.appendChild(title);

  const actions = document.createElement('div');
  actions.className = 'lg-actions';

  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'btn btn-outline-danger btn-sm';
  rm.textContent = 'Remove rule';
  rm.dataset.wwField = `logic-rule-${idx}-remove`;
  rm.disabled = rulesCount <= 1;
  rm.style.display = rulesCount <= 1 ? 'none' : '';
  rm.onclick = removeRule;

  actions.appendChild(rm);

  head.appendChild(leftHead);
  head.appendChild(actions);
  card.appendChild(head);

  const modeSel = ui.select({
    options: [
      { label: 'ALL conditions (AND)', value: 'all' },
      { label: 'ANY condition (OR)', value: 'any' },
    ],
    value: uiCond.mode === 'any' ? 'any' : 'all',
    onChange: async (v) => {
      await updateRule({ ...r, ui: { ...uiCond, mode: v, predicates } }, { structural: true });
    },
  });
  modeSel.dataset.wwField = `logic-rule-${idx}-mode`;

  card.appendChild(ui.labeledNode('Match when', modeSel));

  renderConditions(card, {
    idx,
    rule: r,
    mode: modeSel.value,
    predicates,
    catalogItems,
    updateRule,
  });

  const addPred = document.createElement('button');
  addPred.type = 'button';
  addPred.className = 'btn btn-outline-secondary btn-sm';
  addPred.textContent = 'Add condition';
  addPred.dataset.wwField = `logic-rule-${idx}-add-cond`;
  addPred.onclick = async () => {
    const nextPreds = [...predicates, newPredicate()];
    await updateRule({ ...r, ui: { ...uiCond, mode: modeSel.value, predicates: nextPreds } }, { structural: true });
  };
  card.appendChild(addPred);

  card.appendChild(document.createElement('hr')).className = 'lg-divider';

  const assignHost = document.createElement('div');
  assignHost.dataset.wwField = `logic-rule-${idx}-assignments`;
  renderAssignments(
    assignHost,
    ensureObj(r.assign),
    async (m, { structural = false } = {}) => {
      await updateRule({ ...r, assign: m }, { structural });
    },
    touch,
    { fieldPrefix: `logic-rule-${idx}-assignments` },
  );
  card.appendChild(assignHost);

  card.appendChild(document.createElement('hr')).className = 'lg-divider';

  const thenWrap = document.createElement('div');
  thenWrap.className = 'lg-card';
  thenWrap.dataset.wwField = `logic-rule-${idx}-then`;
  thenWrap.appendChild(ui.help('Outcome if this rule matches.'));
  renderThen(
    thenWrap,
    ensureObj(r.then),
    async (t, { structural = false } = {}) => {
      await updateRule({ ...r, then: t }, { structural });
    },
    touch,
    { fieldPrefix: `logic-rule-${idx}-then` },
  );
  card.appendChild(thenWrap);

  container.appendChild(card);
}
