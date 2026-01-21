// static/js/workflow/executors/logic/ui/rules.js
import { ensureMinRulesAndConds, ruleToBackend, newRule } from '../model.js';
import { renderRuleCard } from './rule-card.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }

export function renderRules(container, { step, rules, catalogItems, updateStepParam, touch, hardRender }) {
  const wrap = document.createElement('div');
  wrap.className = 'lg-wrap';

  const uiRules = ensureArray(rules);

  uiRules.forEach((rule, idx) => {
    const cardHost = document.createElement('div');

    const updateRule = async (nextRule, { structural = false } = {}) => {
      const next = uiRules.slice();
      next[idx] = nextRule;

      const ensured = ensureMinRulesAndConds(next);
      updateStepParam(step.id, '_ui_rules', ensured);
      updateStepParam(step.id, 'rules', ensured.map(ruleToBackend));
      touch();

      if (structural) await hardRender();
    };

    const removeRule = async () => {
      if (uiRules.length <= 1) return;
      const next = uiRules.slice();
      next.splice(idx, 1);

      const ensured = ensureMinRulesAndConds(next.length ? next : [newRule()]);
      updateStepParam(step.id, '_ui_rules', ensured);
      updateStepParam(step.id, 'rules', ensured.map(ruleToBackend));
      touch();
      await hardRender();
    };

    renderRuleCard(cardHost, {
      idx,
      rule,
      rulesCount: uiRules.length,
      catalogItems,
      updateRule,
      removeRule,
      touch,
    });

    wrap.appendChild(cardHost);
  });

  container.appendChild(wrap);
}
