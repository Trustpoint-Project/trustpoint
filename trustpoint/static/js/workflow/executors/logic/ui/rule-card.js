// static/js/workflow/executors/logic/ui/rule-card.js
import { ui } from '../../index.js';
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

  // ---------- header ----------
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

  // ---------- Conditions header + help (LEFT) + AND/OR selector (RIGHT) ----------
  const condTop = document.createElement('div');
  condTop.className = 'lg-conds-top';
  condTop.dataset.wwField = `logic-rule-${ruleId}-conds-top`;

  // Left column: title + help text (this makes the dropdown align with the help line)
  const condLeft = document.createElement('div');
  condLeft.className = 'lg-conds-left';

  const condTitle = document.createElement('div');
  condTitle.className = 'lg-section-title mb-0';
  condTitle.textContent = 'Conditions';

  const condHelp = ui.help('This rule runs only when the conditions below evaluate to true.');

  condLeft.appendChild(condTitle);
  condLeft.appendChild(condHelp);

  // Right column: AND/OR selector
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
      await updateRule(
        { ui: { ...liveUI, mode: normalizeModeStrict(v), predicates: livePreds } },
        { structural: true },
      );
    },
  });
  modeSel.dataset.wwField = `logic-rule-${ruleId}-mode`;

  const modeWrap = document.createElement('div');
  modeWrap.className = 'lg-conds-mode';
  modeWrap.appendChild(ui.labeledNode('Combine with', modeSel));

  condTop.appendChild(condLeft);
  condTop.appendChild(modeWrap);
  card.appendChild(condTop);

  // ---------- conditions list (includes inline "Add condition") ----------
  renderConditions(card, {
    ruleId,
    mode: modeSel.value,
    catalogItems,
    getLiveRule,
    updateRule,
    predicates: snapPredicates,
  });

  // ---------- THEN-BRANCH (only if true) ----------
  card.appendChild(document.createElement('hr')).className = 'lg-divider';

  const branch = document.createElement('div');
  branch.className = 'lg-branch';
  branch.dataset.wwField = `logic-rule-${ruleId}-branch`;

  const branchHead = document.createElement('div');
  branchHead.className = 'lg-branch-head';

  const branchTag = document.createElement('span');
  branchTag.className = 'lg-branch-tag';
  branchTag.textContent = 'IF TRUE';

  const branchHint = document.createElement('div');
  branchHint.className = 'lg-branch-hint';
  branchHint.textContent = 'Runs only when the conditions above match.';

  branchHead.appendChild(branchTag);
  branchHead.appendChild(branchHint);
  branch.appendChild(branchHead);

  const assignTitle = document.createElement('div');
  assignTitle.className = 'lg-section-title';
  assignTitle.textContent = 'Define variables';
  branch.appendChild(assignTitle);

  const assignHost = document.createElement('div');
  assignHost.dataset.wwField = `logic-rule-${ruleId}-assignments`;

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

  branch.appendChild(assignHost);

  const thenTitle = document.createElement('div');
  thenTitle.className = 'lg-section-title mt-2';
  thenTitle.textContent = 'Next';
  branch.appendChild(thenTitle);

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
    { fieldPrefix: `logic-rule-${ruleId}-then`, headline: 'When true' },
  );

  branch.appendChild(thenWrap);

  card.appendChild(branch);
  container.appendChild(card);
}
