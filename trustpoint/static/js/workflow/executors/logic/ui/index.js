// static/js/workflow/executors/logic/ui/index.js
import { ui } from '../../index.js';
import { newRule, newPredicate, ruleToBackend } from '../model.js';
import { renderOperand } from './operand.js';
import { renderThen } from './then.js';
import { renderAssignments } from './assignments.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }
function ensureObj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }

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

  // IMPORTANT: never use stale snapshots for writes.
  // Always read current rules from step.params at the moment of the event.
  const getRules = () => ensureArray(ensureObj(step.params)._ui_rules);
  const setRules = (next) => updateStepParam(step.id, '_ui_rules', next);

  const patchRules = (patchFn) => {
    const cur = getRules();
    const next = patchFn(cur);
    setRules(next);
    syncBackend();
    touch();
    return next;
  };

  const patchRule = (ridx, patchFn) => patchRules((cur) => {
    const next = cur.slice();
    const base = ensureObj(next[ridx]);
    next[ridx] = patchFn(base);
    return next;
  });

  const patchPredicate = (ridx, pidx, patchFn) => patchRule(ridx, (rule) => {
    const r = ensureObj(rule);
    const u = ensureObj(r.ui);
    const preds = ensureArray(u.predicates).slice();
    const basePred = ensureObj(preds[pidx]);
    preds[pidx] = patchFn(basePred);
    return { ...r, ui: { ...u, predicates: preds } };
  });

  // ---- Header
  const top = document.createElement('div');
  top.className = 'lg-topline';
  top.innerHTML = `<strong>Logic</strong>`;
  container.appendChild(top);

  container.appendChild(
    ui.help('Rules are evaluated from top to bottom. The first matching rule runs. If none match, Default runs.'),
  );

  // ---- Rules header + Add rule
  const rulesHead = document.createElement('div');
  rulesHead.className = 'lg-topline mt-3';
  rulesHead.innerHTML = `<div class="lg-section-title mb-0">Rules</div>`;

  const addRuleBtn = document.createElement('button');
  addRuleBtn.type = 'button';
  addRuleBtn.className = 'btn btn-outline-secondary btn-sm';
  addRuleBtn.textContent = 'Add rule';
  addRuleBtn.onclick = async () => {
    patchRules((cur) => [...cur, newRule()]);
    await hardRender();
  };

  rulesHead.appendChild(addRuleBtn);
  container.appendChild(rulesHead);

  const wrap = document.createElement('div');
  wrap.className = 'lg-wrap';
  container.appendChild(wrap);

  // Use a snapshot ONLY for rendering.
  // Writes must use getRules()/patchRules()
  const rulesSnapshot = getRules();

  rulesSnapshot.forEach((rule, ridx) => {
    wrap.appendChild(renderRuleCard({
      step,
      rule: ensureObj(rule),
      ridx,
      getRules,
      patchRules,
      patchRule,
      patchPredicate,
      catalogItems,
      touch,
      hardRender,
    }));
  });

  // ---- Default (ELSE)
  container.appendChild(document.createElement('hr')).className = 'lg-divider';

  const elseTop = document.createElement('div');
  elseTop.className = 'lg-topline';
  elseTop.innerHTML = `<div class="lg-rule-tag else">DEFAULT</div>`;
  container.appendChild(elseTop);

  const defCard = document.createElement('div');
  defCard.className = 'lg-card';
  defCard.appendChild(ui.help('Runs when no rule matched.'));

  const def = ensureObj(ensureObj(step.params).default);
  const a0 = ensureArray(def.actions)[0];
  const defAssign = (a0 && typeof a0 === 'object' && String(a0.type).toLowerCase() === 'set')
    ? ensureObj(a0.assign)
    : {};

  const defAssignMount = document.createElement('div');
  defCard.appendChild(defAssignMount);

  renderAssignments(defAssignMount, defAssign, (nextAssign) => {
    const nextDefault = ensureObj(ensureObj(step.params).default);
    updateStepParam(step.id, 'default', {
      ...nextDefault,
      actions: [{ type: 'set', assign: ensureObj(nextAssign) }],
    });
    syncBackend();
    touch();
  }, touch);

  defCard.appendChild(document.createElement('hr')).className = 'lg-divider';

  const defThenMount = document.createElement('div');
  defCard.appendChild(defThenMount);

  renderThen(defThenMount, ensureObj(def.then), (t) => {
    const nextDefault = ensureObj(ensureObj(step.params).default);
    updateStepParam(step.id, 'default', { ...nextDefault, then: ensureObj(t) });
    syncBackend();
    touch();
  }, touch);

  container.appendChild(defCard);
}

function renderRuleCard({
  step,
  rule,
  ridx,
  getRules,
  patchRules,
  patchRule,
  patchPredicate,
  catalogItems,
  touch,
  hardRender,
}) {
  const r = ensureObj(rule);
  const uiCond = ensureObj(r.ui);
  const predicates = ensureArray(uiCond.predicates);

  const card = document.createElement('div');
  card.className = 'lg-card';

  // Header
  const head = document.createElement('div');
  head.className = 'lg-rule-head';

  const tag = document.createElement('div');
  tag.className = 'lg-rule-tag';
  tag.textContent = ridx === 0 ? 'IF' : 'ELSE IF';

  const title = document.createElement('div');
  title.innerHTML = `<strong>Rule ${ridx + 1}</strong>`;

  const actions = document.createElement('div');
  actions.className = 'lg-actions';

  // Remove rule only if > 1
  if (getRules().length > 1) {
    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'btn btn-outline-danger btn-sm';
    rm.textContent = 'Remove rule';
    rm.onclick = async () => {
      patchRules((cur) => {
        const next = cur.slice();
        next.splice(ridx, 1);
        return next.length ? next : [newRule()];
      });
      await hardRender();
    };
    actions.appendChild(rm);
  }

  head.appendChild(tag);
  head.appendChild(title);
  head.appendChild(actions);
  card.appendChild(head);

  // Combine selector
  const modeSel = ui.select({
    options: [
      { label: 'Match ALL (AND)', value: 'all' },
      { label: 'Match ANY (OR)', value: 'any' },
    ],
    value: uiCond.mode === 'any' ? 'any' : 'all',
    onChange: (v) => {
      patchRule(ridx, (base) => {
        const rr = ensureObj(base);
        const uu = ensureObj(rr.ui);
        return { ...rr, ui: { ...uu, mode: v } };
      });
      updateJoinText(condWrap, v);
    },
  });

  card.appendChild(ui.labeledNode('Conditions', modeSel));

  const condWrap = document.createElement('div');
  condWrap.className = 'lg-conds';
  card.appendChild(condWrap);

  function updateJoinText(root, mode) {
    const txt = String(mode) === 'any' ? 'OR' : 'AND';
    root.querySelectorAll('.lg-join-pill').forEach((el) => { el.textContent = txt; });
  }

  const joinTxt = modeSel.value === 'any' ? 'OR' : 'AND';

  predicates.forEach((pred, pidx) => {
    if (pidx > 0) {
      const join = document.createElement('div');
      join.className = 'lg-join-pill';
      join.textContent = joinTxt;
      condWrap.appendChild(join);
    }

    const box = document.createElement('div');
    box.className = 'lg-cond';

    const grid = document.createElement('div');
    grid.className = 'lg-cond-grid';
    box.appendChild(grid);

    // Left operand
    const leftMount = document.createElement('div');
    renderOperand(
      leftMount,
      ensureObj(pred).left ?? { path: 'ctx.vars.' },
      async (v, opts = { structural: false }) => {
        patchPredicate(ridx, pidx, (bp) => ({ ...ensureObj(bp), left: v }));
        if (opts.structural) await hardRender();
      },
      catalogItems,
    );
    grid.appendChild(ui.labeledNode('Left', leftMount));

    // Operator
    const opSel = ui.select({
      options: [
        { label: 'equals', value: 'eq' },
        { label: 'not equals', value: 'ne' },
        { label: 'exists', value: 'exists' },
        { label: 'is truthy', value: 'truthy' },
        { label: 'is falsy', value: 'falsy' },
      ],
      value: String(ensureObj(pred).op || 'eq'),
      onChange: async (v) => {
        patchPredicate(ridx, pidx, (bp) => ({ ...ensureObj(bp), op: v }));
        // RHS visibility may change => structural rebuild
        await hardRender();
      },
    });
    grid.appendChild(ui.labeledNode('Operator', opSel));

    // Right operand (only if needed)
    const needsRight = ['eq', 'ne'].includes(String(ensureObj(pred).op || 'eq'));
    if (needsRight) {
      const rightMount = document.createElement('div');
      renderOperand(
        rightMount,
        ensureObj(pred).right,
        async (v, opts = { structural: false }) => {
          patchPredicate(ridx, pidx, (bp) => ({ ...ensureObj(bp), right: v }));
          if (opts.structural) await hardRender();
        },
        catalogItems,
      );
      grid.appendChild(ui.labeledNode('Right', rightMount));
    } else {
      const stub = document.createElement('div');
      stub.appendChild(ui.help('No right-hand value needed.'));
      grid.appendChild(stub);
    }

    // Condition actions
    const condActions = document.createElement('div');
    condActions.className = 'lg-cond-actions';
    box.appendChild(condActions);

    // Remove condition only if >1
    if (predicates.length > 1) {
      const rmC = document.createElement('button');
      rmC.type = 'button';
      rmC.className = 'btn btn-outline-danger btn-sm';
      rmC.textContent = 'Remove condition';
      rmC.onclick = async () => {
        patchRule(ridx, (base) => {
          const rr = ensureObj(base);
          const uu = ensureObj(rr.ui);
          const np = ensureArray(uu.predicates).slice();
          np.splice(pidx, 1);
          return { ...rr, ui: { ...uu, predicates: np.length ? np : [newPredicate()] } };
        });
        await hardRender();
      };
      condActions.appendChild(rmC);
    }

    condWrap.appendChild(box);
  });

  // Add condition
  const addCond = document.createElement('button');
  addCond.type = 'button';
  addCond.className = 'btn btn-outline-secondary btn-sm';
  addCond.textContent = 'Add condition';
  addCond.onclick = async () => {
    patchRule(ridx, (base) => {
      const rr = ensureObj(base);
      const uu = ensureObj(rr.ui);
      const np = ensureArray(uu.predicates).slice();
      np.push(newPredicate());
      return { ...rr, ui: { ...uu, predicates: np } };
    });
    await hardRender();
  };
  card.appendChild(addCond);

  // Assignments
  card.appendChild(document.createElement('hr')).className = 'lg-divider';
  const assignMount = document.createElement('div');
  card.appendChild(assignMount);

  renderAssignments(assignMount, ensureObj(r.assign), (nextAssign) => {
    patchRule(ridx, (base) => ({ ...ensureObj(base), assign: ensureObj(nextAssign) }));
  }, touch);

  // Then
  card.appendChild(document.createElement('hr')).className = 'lg-divider';
  const thenMount = document.createElement('div');
  card.appendChild(thenMount);

  renderThen(thenMount, ensureObj(r.then), (t) => {
    patchRule(ridx, (base) => ({ ...ensureObj(base), then: ensureObj(t) }));
  }, touch);

  // WHEN preview (computed)
  const preview = document.createElement('pre');
  preview.className = 'lg-preview mt-3';
  preview.textContent = JSON.stringify(ruleToBackend(r).when, null, 2);
  card.appendChild(ui.labeledNode('WHEN (computed)', preview));

  updateJoinText(condWrap, modeSel.value);
  return card;
}
