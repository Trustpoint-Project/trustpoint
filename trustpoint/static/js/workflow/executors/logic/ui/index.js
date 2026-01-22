// static/js/workflow/executors/logic/ui/index.js
import { ui } from '../../index.js';
import { newRule } from '../model.js';
import { renderRules } from './rules.js';
import { renderDefaultBlock } from './default.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

export function renderLogicParamsUI(container, {
  step,
  params,
  catalogItems,
  updateStepParam,
  touch,
  hardRender,
  syncBackend,
}) {
  container.textContent = '';

  // Header
  const top = document.createElement('div');
  top.className = 'lg-topline';
  top.innerHTML = `<strong>Logic</strong>`;
  top.dataset.wwField = 'logic-title';
  container.appendChild(top);

  container.appendChild(
    ui.help('Rules are evaluated from top to bottom. The first matching rule runs. If none match, Default runs.'),
  );

  // Rules header + Add rule
  const rulesHead = document.createElement('div');
  rulesHead.className = 'lg-topline mt-3';
  rulesHead.innerHTML = `<div class="lg-section-title mb-0">Rules</div>`;

  const addRuleBtn = document.createElement('button');
  addRuleBtn.type = 'button';
  addRuleBtn.className = 'btn btn-outline-secondary btn-sm';
  addRuleBtn.textContent = 'Add rule';
  addRuleBtn.dataset.wwField = 'logic-add-rule';
  addRuleBtn.onclick = async () => {
    // IMPORTANT: read/write live state (no stale params snapshot)
    const cur = ensureArray(ensureObj(step.params)._ui_rules);
    const next = [...cur, newRule()];
    updateStepParam(step.id, '_ui_rules', next);
    syncBackend?.();
    touch?.();
    await hardRender?.();
  };

  rulesHead.appendChild(addRuleBtn);
  container.appendChild(rulesHead);

  // Rules list
  const rulesWrapHost = document.createElement('div');
  rulesWrapHost.dataset.wwField = 'logic-rules-host';
  container.appendChild(rulesWrapHost);

  const uiRules = ensureArray(ensureObj(params)._ui_rules);
  renderRules(rulesWrapHost, {
    step,
    rules: uiRules,
    catalogItems,
    updateStepParam,
    touch: () => { syncBackend?.(); touch?.(); },
    hardRender,
  });

  // Default
  container.appendChild(document.createElement('hr')).className = 'lg-divider';

  const defHost = document.createElement('div');
  defHost.dataset.wwField = 'logic-default-host';
  container.appendChild(defHost);

  renderDefaultBlock(defHost, {
    step,
    params,
    updateStepParam,
    touch: () => { syncBackend?.(); touch?.(); },
    hardRender,
  });
}
