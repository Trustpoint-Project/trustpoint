// static/js/workflow/executors/logic/ui/default.js
import { ui } from '../../index.js';
import { renderAssignments } from './assignments.js';
import { renderThen } from './then.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

function getLiveDefault(step) {
  const p = ensureObj(step?.params);
  const def = ensureObj(p.default);

  if (!Array.isArray(def.actions)) def.actions = [];
  if (!def.then || typeof def.then !== 'object') def.then = { pass: true };

  return def;
}

export function renderDefaultBlock(container, { step, params, updateStepParam, touch, hardRender }) {
  container.textContent = '';

  const p = ensureObj(params);
  void p;

  const elseTop = document.createElement('div');
  elseTop.className = 'lg-topline';
  elseTop.dataset.wwField = 'logic-default-top';
  elseTop.innerHTML = `<div class="lg-rule-tag else">ELSE</div><strong>Default</strong>`;
  container.appendChild(elseTop);

  const defCard = document.createElement('div');
  defCard.className = 'lg-card';
  defCard.dataset.wwField = 'logic-default-card';
  defCard.appendChild(ui.help('Runs when no rule matched.'));

  const liveDef0 = getLiveDefault(step);

  const defAssign = (() => {
    const a0 = ensureArray(liveDef0.actions)[0];
    if (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set') {
      return ensureObj(a0.assign);
    }
    return {};
  })();

  const assignHost = document.createElement('div');
  assignHost.dataset.wwField = 'logic-default-assignments';

  renderAssignments(
    assignHost,
    defAssign,
    async (m, { structural = false } = {}) => {
      const liveDef = getLiveDefault(step);
      updateStepParam(step.id, 'default', { ...liveDef, actions: [{ type: 'set', assign: ensureObj(m) }] });
      touch?.();
      if (structural) await hardRender?.();
    },
    touch,
    {
      fieldPrefix: 'logic-default-assignments',
      getLiveAssign: () => {
        const liveDef = getLiveDefault(step);
        const a0 = ensureArray(liveDef.actions)[0];
        if (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set') {
          return ensureObj(a0.assign);
        }
        return {};
      },
    },
  );

  defCard.appendChild(assignHost);

  defCard.appendChild(document.createElement('hr')).className = 'lg-divider';

  const thenWrap = document.createElement('div');
  thenWrap.className = 'lg-card';
  thenWrap.dataset.wwField = 'logic-default-then';
  thenWrap.appendChild(ui.help('Outcome for Default (ELSE).'));

  renderThen(
    thenWrap,
    ensureObj(liveDef0.then),
    async (t, { structural = false } = {}) => {
      const liveDef = getLiveDefault(step);
      updateStepParam(step.id, 'default', { ...liveDef, then: ensureObj(t) });
      touch?.();
      if (structural) await hardRender?.();
    },
    touch,
    { fieldPrefix: 'logic-default-then', headline: 'Default outcome' },
  );

  defCard.appendChild(thenWrap);
  container.appendChild(defCard);
}
