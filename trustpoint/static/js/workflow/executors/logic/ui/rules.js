// static/js/workflow/executors/logic/ui/rules.js
import { ensureMinRulesAndConds, ruleToBackend, newRule } from '../model.js';
import { renderRuleCard } from './rule-card.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }
function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }

export function renderRules(container, { step, rules, catalogItems, updateStepParam, touch, hardRender }) {
  container.textContent = '';

  const wrap = document.createElement('div');
  wrap.className = 'lg-wrap';
  wrap.dataset.wwField = 'logic-rules-wrap';

  const snapshot = ensureArray(rules);

  const getLiveRules = () => ensureArray(ensureObj(step.params)._ui_rules);

  const findLiveIndexByRuleId = (ruleId) => {
    const live = getLiveRules();
    return live.findIndex((r) => String(ensureObj(r)._id || '') === String(ruleId || ''));
  };

  const getLiveRuleById = (ruleId) => {
    const i = findLiveIndexByRuleId(ruleId);
    if (i < 0) return {};
    return ensureObj(getLiveRules()[i]);
  };

  snapshot.forEach((ruleSnap) => {
    const ruleId = String(ensureObj(ruleSnap)._id || '');

    const cardHost = document.createElement('div');
    cardHost.dataset.wwField = `logic-rule-host-${ruleId || 'noid'}`;

    const updateRule = async (patch, { structural = false } = {}) => {
      const live = getLiveRules();
      const idx = findLiveIndexByRuleId(ruleId);
      if (idx < 0) return;

      const base = ensureObj(live[idx]);
      const next = live.slice();

      const p = ensureObj(patch);

      const merged = { ...base, ...p };
      if ('ui' in p) merged.ui = ensureObj(p.ui);
      if ('assign' in p) merged.assign = ensureObj(p.assign);
      if ('then' in p) merged.then = ensureObj(p.then);

      next[idx] = merged;

      const ensured = ensureMinRulesAndConds(next);
      updateStepParam(step.id, '_ui_rules', ensured);
      updateStepParam(step.id, 'rules', ensured.map(ruleToBackend));
      touch?.();

      if (structural) await hardRender?.();
    };

    const removeRule = async () => {
      const live = getLiveRules();
      const idx = findLiveIndexByRuleId(ruleId);
      if (idx < 0) return;
      if (live.length <= 1) return;

      const next = live.slice();
      next.splice(idx, 1);

      const ensured = ensureMinRulesAndConds(next.length ? next : [newRule()]);
      updateStepParam(step.id, '_ui_rules', ensured);
      updateStepParam(step.id, 'rules', ensured.map(ruleToBackend));
      touch?.();
      await hardRender?.();
    };

    renderRuleCard(cardHost, {
      ruleId,
      rule: ruleSnap, // snapshot for display
      rulesCount: snapshot.length,
      catalogItems,
      getLiveRule: () => getLiveRuleById(ruleId),
      updateRule,
      removeRule,
      touch,
    });

    wrap.appendChild(cardHost);
  });

  container.appendChild(wrap);
}
