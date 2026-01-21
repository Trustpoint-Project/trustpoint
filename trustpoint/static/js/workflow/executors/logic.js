// static/js/workflow/executors/logic.js
import { register } from './index.js';
import {
  ensureLogicDefaults,
  ensureMinRulesAndConds,
  newRule,
  ruleToBackend,
  defaultToBackend,
} from './logic/model.js';
import { injectStylesOnce } from './logic/styles.js';
import { getCatalogItems } from './logic/catalog.js';
import { renderLogicParamsUI } from './logic/ui/index.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

function syncBackendFromParams(step, updateStepParam) {
  const p = ensureLogicDefaults(ensureObj(step.params));
  const uiRules = ensureArray(p._ui_rules);
  updateStepParam(step.id, 'rules', uiRules.map(ruleToBackend));
  updateStepParam(step.id, 'default', defaultToBackend(p.default));
}

register('Logic', {
  getDefaultParams() {
    return {
      _ui_rules: [newRule()],
      rules: [],
      default: { actions: [{ type: 'set', assign: {} }], then: { pass: true } },
    };
  },

  async renderParams(container, step, { updateStepParam, onChange }) {
    injectStylesOnce();

    // Ensure minimums once, without looping:
    const p = ensureLogicDefaults(ensureObj(step.params));
    const ensured = ensureMinRulesAndConds(p._ui_rules);

    if (ensured !== p._ui_rules) {
      updateStepParam(step.id, '_ui_rules', ensured);
      // Sync backend ONCE here, but do not trigger any full UI rebuild.
      syncBackendFromParams(step, updateStepParam);
      onChange?.();
    }

    // Cache catalog separately (your catalog.js should already do this)
    const catalogItems = await getCatalogItems();

    // Soft touch: preview/validation only; MUST NOT rebuild the Logic DOM.
    let softScheduled = false;
    const touch = () => {
      if (softScheduled) return;
      softScheduled = true;
      queueMicrotask(() => {
        softScheduled = false;
        onChange?.();
      });
    };

    // Hard render: rebuild the Logic DOM, but ONLY when structure changes.
    const hardRender = async () => {
      container.textContent = '';
      renderLogicParamsUI(container, {
        step,
        params: ensureLogicDefaults(ensureObj(step.params)),
        catalogItems,
        updateStepParam,
        touch,
        hardRender,
        syncBackend: () => syncBackendFromParams(step, updateStepParam),
      });
    };

    await hardRender();
  },

  validate(params) {
    const errs = [];
    const p = ensureObj(params);
    if (!p.default || typeof p.default !== 'object') errs.push('Logic: default is required.');
    if (!Array.isArray(p.rules)) errs.push('Logic: rules must be an array.');
    return errs;
  },
});
