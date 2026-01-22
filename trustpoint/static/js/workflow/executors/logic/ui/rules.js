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

  // Render snapshot only
  const snapshot = ensureArray(rules);

  // Live getters to prevent stale overwrites
  const getLiveRules = () => ensureArray(ensureObj(step.params)._ui_rules);

  snapshot.forEach((rule, idx) => {
    const cardHost = document.createElement('div');
    cardHost.dataset.wwField = `logic-rule-host-${idx}`;

    const updateRule = async (nextRule, { structural = false } = {}) => {
      // Always base on LIVE rules, not on the render snapshot
      const live = getLiveRules();
      const next = live.slice();
      next[idx] = nextRule;

      const ensured = ensureMinRulesAndConds(next);
      updateStepParam(step.id, '_ui_rules', ensured);
      updateStepParam(step.id, 'rules', ensured.map(ruleToBackend));
      touch?.();

      if (structural) await hardRender?.();
    };

    const removeRule = async () => {
      const live = getLiveRules();
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
      idx,
      rule,
      rulesCount: snapshot.length,
      catalogItems,
      updateRule,
      removeRule,
      touch,
    });

    wrap.appendChild(cardHost);
  });

  container.appendChild(wrap);
}
