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

// Per-container token so multiple Logic steps do not cancel each other.
const _tokenByContainer = new WeakMap();
function nextToken(container) {
  const cur = _tokenByContainer.get(container) || 0;
  const next = cur + 1;
  _tokenByContainer.set(container, next);
  return next;
}
function isCurrent(container, token) {
  return (_tokenByContainer.get(container) || 0) === token;
}

/**
 * Prevent scroll jumps caused by re-rendering a Logic block above the active field.
 * Keeps the currently focused element at the same viewport Y position.
 *
 * IMPORTANT: When we hard re-render, the active element is destroyed.
 * The old implementation could not restore focus because it tried to re-focus
 * the *old* node reference. This version restores by stable data-ww-field key.
 */
function preserveActiveViewportPosition(domWriteFn, rootContainer) {
  const active = (document.activeElement instanceof HTMLElement) ? document.activeElement : null;

  // Capture a stable key for the active control (set throughout Logic UI).
  const activeKey = active?.dataset?.wwField ? String(active.dataset.wwField) : null;

  const beforeTop = (active && document.contains(active)) ? active.getBoundingClientRect().top : null;

  // Optional selection snapshot (safe for inputs/textarea only).
  let sel = null;
  if (active && (active instanceof HTMLInputElement || active instanceof HTMLTextAreaElement)) {
    try { sel = { start: active.selectionStart, end: active.selectionEnd }; } catch { sel = null; }
  }

  domWriteFn();

  // Restore on next frame after layout settles.
  requestAnimationFrame(() => {
    if (!rootContainer || !(rootContainer instanceof HTMLElement)) return;

    // Restore scroll anchoring (best effort).
    if (beforeTop != null && activeKey) {
      const fresh = rootContainer.querySelector(`[data-ww-field="${CSS.escape(activeKey)}"]`);
      if (fresh instanceof HTMLElement) {
        const afterTop = fresh.getBoundingClientRect().top;
        const delta = afterTop - beforeTop;
        if (delta) {
          try { window.scrollBy(0, delta); } catch {}
        }
      }
    }

    // Restore focus + selection on the newly rendered control.
    if (!activeKey) return;
    const el = rootContainer.querySelector(`[data-ww-field="${CSS.escape(activeKey)}"]`);
    if (!(el instanceof HTMLElement)) return;

    try { el.focus({ preventScroll: true }); } catch { try { el.focus(); } catch {} }

    if (sel && (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement)) {
      try { el.setSelectionRange(sel.start ?? 0, sel.end ?? 0); } catch {}
    }
  });
}

register('Logic', {
  getDefaultParams() {
    return {
      _ui_rules: [newRule()],
      rules: [],
      default: { actions: [{ type: 'set', assign: {} }], then: { pass: true } },
    };
  },

  renderParams(container, step, { updateStepParam, onChange }) {
    injectStylesOnce();

    // Ensure minimum structure once.
    const p = ensureLogicDefaults(ensureObj(step.params));
    const ensured = ensureMinRulesAndConds(p._ui_rules);

    if (ensured !== p._ui_rules) {
      updateStepParam(step.id, '_ui_rules', ensured);
      syncBackendFromParams(step, updateStepParam);
      onChange?.();
    }

    // Soft touch only (no UI rebuild).
    let softScheduled = false;
    const touch = () => {
      if (softScheduled) return;
      softScheduled = true;
      queueMicrotask(() => {
        softScheduled = false;
        onChange?.();
      });
    };

    const token = nextToken(container);

    // Local catalog state for this container.
    let lastCatalogItems = [];

    const hardRender = async () => {
      if (!container.isConnected) return;
      if (!isCurrent(container, token)) return;

      preserveActiveViewportPosition(() => {
        container.textContent = '';
        renderLogicParamsUI(container, {
          step,
          params: ensureLogicDefaults(ensureObj(step.params)),
          catalogItems: lastCatalogItems,
          updateStepParam,
          touch,
          hardRender,
          syncBackend: () => syncBackendFromParams(step, updateStepParam),
        });
      }, container);
    };

    // First render immediately (no catalog yet).
    hardRender();

    // Load catalog async, then rerender deterministically if still current.
    (async () => {
      const items = await getCatalogItems().catch(() => []);
      if (!container.isConnected) return;
      if (!isCurrent(container, token)) return;

      lastCatalogItems = Array.isArray(items) ? items : [];
      await hardRender();
    })();
  },

  validate(params) {
    const errs = [];
    const p = ensureObj(params);
    if (!p.default || typeof p.default !== 'object') errs.push('Logic: default is required.');
    if (!Array.isArray(p.rules)) errs.push('Logic: rules must be an array.');
    return errs;
  },
});
