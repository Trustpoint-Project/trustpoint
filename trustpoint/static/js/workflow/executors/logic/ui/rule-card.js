// static/js/workflow/executors/logic/ui/rule-card.js
import { ui } from '../../index.js';
import { newPredicate } from '../model.js';
import { renderConditions } from './rule-conditions.js';
import { renderAssignments } from './assignments.js';
import { renderThen } from './then.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

function normalizeModeStrict(raw) {
  const m = String(raw || '').trim().toLowerCase();
  return (m === 'or') ? 'or' : 'and';
}

export function renderRuleCard(container, {
  ruleId,
  displayIndex,
  rulesCount,
  rule,
  catalogItems,
  getLiveRule,
  updateRule,
  removeRule,
  touch,
}) {
  container.textContent = '';

  const snapRule = ensureObj(rule);
  const snapUI = ensureObj(snapRule.ui);
  const snapPredicates = ensureArray(snapUI.predicates);

  const card = document.createElement('div');
  card.className = 'lg-card';
  card.dataset.wwField = `logic-rule-${ruleId || 'noid'}`;

  const head = document.createElement('div');
  head.className = 'lg-rule-head';

  const leftHead = document.createElement('div');
  leftHead.className = 'd-flex align-items-center gap-2 flex-wrap';

  const tag = document.createElement('span');
  tag.className = 'lg-rule-tag';
  tag.textContent = (displayIndex === 0) ? 'IF' : 'ELSE IF';

  const title = document.createElement('strong');
  title.textContent = `Rule ${Number(displayIndex) + 1}`;

  leftHead.appendChild(tag);
  leftHead.appendChild(title);

  const actions = document.createElement('div');
  actions.className = 'lg-actions';

  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'btn btn-outline-danger btn-sm';
  rm.textContent = 'Remove rule';
  rm.dataset.wwField = `logic-rule-${ruleId}-remove`;
  rm.disabled = rulesCount <= 1;
  rm.style.display = rulesCount <= 1 ? 'none' : '';
  rm.onclick = removeRule;

  actions.appendChild(rm);

  head.appendChild(leftHead);
  head.appendChild(actions);
  card.appendChild(head);

  const modeSel = ui.select({
    options: [
      { label: 'AND', value: 'and' },
      { label: 'OR', value: 'or' },
    ],
    value: normalizeModeStrict(snapUI.mode),
    onChange: async (v) => {
      const live = ensureObj(getLiveRule?.());
      const liveUI = ensureObj(live.ui);
      const livePreds = ensureArray(liveUI.predicates);
      await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(v), predicates: livePreds } }, { structural: true });
    },
  });
  modeSel.dataset.wwField = `logic-rule-${ruleId}-mode`;

  card.appendChild(ui.labeledNode('', modeSel));

  renderConditions(card, {
    ruleId,
    mode: modeSel.value,
    catalogItems,
    getLiveRule,
    updateRule,
    predicates: snapPredicates,
  });

  const addPred = document.createElement('button');
  addPred.type = 'button';
  addPred.className = 'btn btn-outline-secondary btn-sm';
  addPred.textContent = 'Add condition';
  addPred.dataset.wwField = `logic-rule-${ruleId}-add-cond`;
  addPred.onclick = async () => {
    const live = ensureObj(getLiveRule?.());
    const liveUI = ensureObj(live.ui);
    const livePreds = ensureArray(liveUI.predicates);
    const nextPreds = [...livePreds, newPredicate()];
    await updateRule({ ui: { ...liveUI, mode: normalizeModeStrict(modeSel.value), predicates: nextPreds } }, { structural: true });
  };
  card.appendChild(addPred);

  card.appendChild(document.createElement('hr')).className = 'lg-divider';

  const assignHost = document.createElement('div');
  assignHost.dataset.wwField = `logic-rule-${ruleId}-assignments`;

  const assignTitle = document.createElement('div');
  assignTitle.className = 'lg-section-title';
  assignTitle.textContent = 'Define variables';
  card.appendChild(assignTitle);

  renderAssignments(
    assignHost,
    ensureObj(snapRule.assign),
    async (m, { structural = false } = {}) => {
      await updateRule({ assign: ensureObj(m) }, { structural });
      touch?.();
    },
    touch,
    {
      fieldPrefix: `logic-rule-${ruleId}-assignments`,
      getLiveAssign: () => ensureObj(ensureObj(getLiveRule?.()).assign),
    },
  );

  card.appendChild(assignHost);

  card.appendChild(document.createElement('hr')).className = 'lg-divider';

  const thenTitle = document.createElement('div');
  thenTitle.className = 'lg-section-title';
  thenTitle.textContent = 'Then';
  card.appendChild(thenTitle);

  const thenWrap = document.createElement('div');
  thenWrap.dataset.wwField = `logic-rule-${ruleId}-then`;

  renderThen(
    thenWrap,
    ensureObj(snapRule.then),
    async (t, { structural = false } = {}) => {
      await updateRule({ then: ensureObj(t) }, { structural });
      touch?.();
    },
    touch,
    { fieldPrefix: `logic-rule-${ruleId}-then`, headline: 'If true' },
  );

  card.appendChild(thenWrap);

  container.appendChild(card);
}
