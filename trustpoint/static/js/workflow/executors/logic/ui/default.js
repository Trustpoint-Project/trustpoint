// static/js/workflow/executors/logic/ui/default.js
import { ui } from '../../index.js';
import { renderAssignments } from './assignments.js';
import { renderThen } from './then.js';

function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
function ensureArray(v) { return Array.isArray(v) ? v : []; }

export function renderDefaultBlock(container, { step, params, updateStepParam, touch, hardRender }) {
  const p = ensureObj(params);
  const def = ensureObj(p.default);

  if (!def.actions || !Array.isArray(def.actions)) def.actions = [];
  if (!def.then || typeof def.then !== 'object') def.then = { pass: true };

  const elseTop = document.createElement('div');
  elseTop.className = 'lg-topline';
  elseTop.innerHTML = `<div class="lg-rule-tag else">ELSE</div><strong>Default</strong>`;
  container.appendChild(elseTop);

  const defCard = document.createElement('div');
  defCard.className = 'lg-card';
  defCard.appendChild(ui.help('Runs when no rule matched.'));

  const defAssign = (() => {
    const a0 = ensureArray(def.actions)[0];
    if (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set') {
      return ensureObj(a0.assign);
    }
    return {};
  })();

  const assignHost = document.createElement('div');
  renderAssignments(assignHost, defAssign, async (m, { structural = false } = {}) => {
    updateStepParam(step.id, 'default', { ...def, actions: [{ type: 'set', assign: m }] });
    touch();
    if (structural) await hardRender();
  }, touch);
  defCard.appendChild(assignHost);

  defCard.appendChild(document.createElement('hr')).className = 'lg-divider';

  const thenWrap = document.createElement('div');
  thenWrap.className = 'lg-card';
  thenWrap.appendChild(ui.help('Outcome for Default (ELSE).'));
  renderThen(thenWrap, ensureObj(def.then), async (t, { structural = false } = {}) => {
    updateStepParam(step.id, 'default', { ...def, then: t });
    touch();
    if (structural) await hardRender();
  }, touch);

  defCard.appendChild(thenWrap);
  container.appendChild(defCard);
}
