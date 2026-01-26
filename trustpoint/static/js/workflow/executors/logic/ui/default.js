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

  container.appendChild(ui.help('Runs when no IF rule matched.'));

  const defCard = document.createElement('div');
  defCard.className = 'lg-card';
  defCard.dataset.wwField = 'logic-default-card';

  const branch = document.createElement('div');
  branch.className = 'lg-branch lg-branch-else';
  branch.dataset.wwField = 'logic-default-branch';

  const branchHead = document.createElement('div');
  branchHead.className = 'lg-branch-head';

  const branchTag = document.createElement('span');
  branchTag.className = 'lg-branch-tag';
  branchTag.textContent = 'ELSE';

  const branchHint = document.createElement('div');
  branchHint.className = 'lg-branch-hint';
  branchHint.textContent = 'Runs when none of the IF rules are true.';

  branchHead.appendChild(branchTag);
  branchHead.appendChild(branchHint);
  branch.appendChild(branchHead);

  const liveDef0 = getLiveDefault(step);

  const defAssign = (() => {
    const a0 = ensureArray(liveDef0.actions)[0];
    if (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set') {
      return ensureObj(a0.assign);
    }
    return {};
  })();

  const assignTitle = document.createElement('div');
  assignTitle.className = 'lg-section-title';
  assignTitle.textContent = 'Define variables';
  branch.appendChild(assignTitle);

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

  branch.appendChild(assignHost);

  const thenTitle = document.createElement('div');
  thenTitle.className = 'lg-section-title mt-2';
  thenTitle.textContent = 'Next';
  branch.appendChild(thenTitle);

  const thenWrap = document.createElement('div');
  thenWrap.dataset.wwField = 'logic-default-then';

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
    { fieldPrefix: 'logic-default-then', headline: 'Default path' },
  );

  branch.appendChild(thenWrap);

  defCard.appendChild(branch);
  container.appendChild(defCard);
}
