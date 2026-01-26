// static/js/workflow/steps.js
import {
  state, addStep, removeStep, updateStepType, updateStepParam,
} from './state.js';
import { getTypes, get as getExecutor } from './executors/index.js';
import { bindStepsDnD } from './steps-dnd.js';

// Side-effect imports (register executors) — REQUIRED
import './executors/approval.js';
import './executors/email.js';
import './executors/webhook.js';
import './executors/logic.js';

let _stylesInjected = false;
function injectStylesOnce() {
  if (_stylesInjected) return;
  _stylesInjected = true;

  const style = document.createElement('style');
  style.textContent = `
    .ww-step-card { border-radius:.6rem; border:1px solid var(--bs-border-color,#dee2e6); }
    .ww-step-header { border-radius:.5rem; padding:.5rem .75rem; }
    .ww-drag-handle { cursor: grab; user-select:none; font-size:1.1rem; opacity:.7; }

    /* Drag state: no opacity; use outline. */
    .ww-dragging { opacity: 1; outline: 2px solid var(--bs-primary,#0d6efd); outline-offset: 2px; }

    .ww-drop-indicator-top { box-shadow: 0 -2px 0 0 var(--bs-primary,#0d6efd) inset; }
    .ww-drop-indicator-bottom { box-shadow: 0 2px 0 0 var(--bs-primary,#0d6efd) inset; }

    .ww-step-badge {
      display:inline-block;
      font-size:.75rem;
      padding:.15rem .45rem;
      border-radius:999px;
      border:1px solid rgba(220,53,69,.35);
      color: rgba(220,53,69,1);
      background: rgba(220,53,69,.08);
      margin-left:.5rem;
      vertical-align: middle;
      line-height: 1.2;
    }
    .ww-step-note {
      font-size:.85rem;
      border:1px solid rgba(220,53,69,.25);
      background: rgba(220,53,69,.06);
      border-radius:.5rem;
      padding:.5rem .6rem;
      margin:.25rem 0 .5rem;
    }

    #steps-list, .ww-step-card, .ww-step-card * {
      overflow-anchor: none;
    }

    .ww-collapse-btn {
      border: none;
      background: transparent;
      padding: .1rem .35rem;
      line-height: 1;
      border-radius: .35rem;
      color: var(--bs-secondary-color,#6c757d);
    }
    .ww-collapse-btn:hover {
      background: rgba(0,0,0,.04);
    }
    .ww-step-collapsed .ww-step-body {
      display: none !important;
    }

    /* ----- Header layout (title + note input) ----- */
    .ww-step-head-left {
      display:flex;
      align-items:center;
      gap:.5rem;
      min-width: 0; /* allow ellipsis */
      flex: 1 1 auto;
    }
    .ww-step-title {
      min-width: 0;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .ww-step-note-input {
      flex: 0 1 340px;           /* fits nicely on desktop */
      min-width: 180px;
      max-width: 520px;
    }
    @media (max-width: 768px) {
      .ww-step-note-input { flex: 1 1 100%; min-width: 140px; }
      .ww-step-head-left { flex-wrap: wrap; }
      .ww-step-title { flex: 1 1 100%; }
    }
  `;
  document.head.appendChild(style);
}

function allowedStepTypesForEvent({ handler }, allTypes) {
  const h = String(handler || '').trim();
  if (!h) return allTypes;

  if (h === 'device_action') {
    const allowed = new Set(['Webhook', 'Email', 'Logic']);
    return allTypes.filter((t) => allowed.has(t));
  }

  if (h === 'certificate_request') return allTypes;

  return allTypes;
}

function computeAllowedTypes() {
  const all = getTypes();
  const allowed = allowedStepTypesForEvent(
    { handler: state.handler, protocol: state.protocol, operation: state.operation },
    all,
  );
  const set = new Set(Array.isArray(allowed) ? allowed : all);
  return { allTypes: all, allowedTypes: all.filter((t) => set.has(t)), allowedSet: set };
}

function getDefaultParamsForType(type) {
  const exec = getExecutor(type);
  if (!exec || typeof exec.getDefaultParams !== 'function') return {};
  try {
    const p = exec.getDefaultParams();
    return (p && typeof p === 'object' && !Array.isArray(p)) ? p : {};
  } catch {
    return {};
  }
}

function setStepParamsToDefaults(stepId, type) {
  const defaults = getDefaultParamsForType(type);

  const s = state.steps.find((x) => x.id === stepId);
  if (!s || !s.params || typeof s.params !== 'object' || Array.isArray(s.params)) return;

  const keepCollapsed = s.params._ui_collapsed === true;
  const keepNote = (typeof s.params.note === 'string') ? s.params.note : '';

  Object.keys(s.params).forEach((k) => { delete s.params[k]; });
  Object.entries(defaults).forEach(([k, v]) => updateStepParam(stepId, k, v));

  if (keepCollapsed) updateStepParam(stepId, '_ui_collapsed', true);
  if (keepNote) updateStepParam(stepId, 'note', keepNote);
}

const _stepCardMap = new Map();
function _clearStepDomCache() { _stepCardMap.clear(); }

export function renderStepsUI({ containerEl, addBtnEl, onChange }) {
  injectStylesOnce();
  if (!containerEl || !addBtnEl) return;

  const { allowedTypes } = computeAllowedTypes();

  if (!allowedTypes.length) {
    addBtnEl.disabled = true;
    addBtnEl.title = 'No step types available for this event selection.';
  } else {
    addBtnEl.disabled = false;
    addBtnEl.title = '';
  }

  if (!_stepCardMap.size && containerEl.children.length === 0) {
    // ok
  } else if (_stepCardMap.size && containerEl.children.length === 0) {
    _clearStepDomCache();
  }

  const seen = new Set();

  state.steps.forEach((step, idx) => {
    if (!step) return;
    seen.add(step.id);

    const existing = _stepCardMap.get(step.id);
    if (existing && existing.isConnected) {
      const title = existing.querySelector('[data-ww-role="step-title"]');
      if (title) title.textContent = `Step ${idx + 1} • ${step.type}`;

      const collapsed = step?.params?._ui_collapsed === true;
      existing.classList.toggle('ww-step-collapsed', collapsed);

      const btn = existing.querySelector('button[data-ww-role="collapse-btn"]');
      if (btn) btn.textContent = collapsed ? '▸' : '▾';

      const sel = existing.querySelector('select[data-ww-field="step-type"]');
      if (sel instanceof HTMLSelectElement && document.activeElement !== sel) sel.value = step.type;

      const noteInp = existing.querySelector('input[data-ww-field="step-note"]');
      if (noteInp instanceof HTMLInputElement && document.activeElement !== noteInp) {
        noteInp.value = String(step?.params?.note || '');
      }

      return;
    }

    const card = stepCard(step, idx, { containerEl, onChange });
    _stepCardMap.set(step.id, card);
    containerEl.appendChild(card);
  });

  for (const [id, node] of Array.from(_stepCardMap.entries())) {
    if (!seen.has(id)) {
      try { node.remove(); } catch {}
      _stepCardMap.delete(id);
    }
  }

  addBtnEl.onclick = () => {
    const { allowedTypes: allowedNow } = computeAllowedTypes();
    const firstAllowed = allowedNow[0];
    if (!firstAllowed) return;

    addStep(firstAllowed, getDefaultParamsForType(firstAllowed));
    const step = state.steps[state.steps.length - 1];
    if (!step) return;

    const card = stepCard(step, state.steps.length - 1, { containerEl, onChange });
    _stepCardMap.set(step.id, card);
    containerEl.appendChild(card);

    onChange?.();
    bindStepsDnD(containerEl, onChange, _stepCardMap);
  };

  bindStepsDnD(containerEl, onChange, _stepCardMap);
}

function stepCard(step, displayIndex, ctx) {
  const { onChange, containerEl } = ctx;
  const { allTypes, allowedTypes, allowedSet } = computeAllowedTypes();

  const isAllowed = allowedSet.has(step.type);

  const card = document.createElement('div');
  card.className = 'card ww-step-card mb-2 p-2';
  card.dataset.stepId = String(step.id);

  const collapsed = step?.params?._ui_collapsed === true;
  card.classList.toggle('ww-step-collapsed', collapsed);

  const header = document.createElement('div');
  header.className = 'ww-step-header d-flex justify-content-between align-items-center mb-2';

  const left = document.createElement('div');
  left.className = 'ww-step-head-left';

  const grip = document.createElement('span');
  grip.className = 'ww-drag-handle';
  grip.title = 'Drag to reorder';
  grip.textContent = '⋮⋮';
  grip.setAttribute('draggable', 'true');

  const collapseBtn = document.createElement('button');
  collapseBtn.type = 'button';
  collapseBtn.className = 'ww-collapse-btn';
  collapseBtn.dataset.wwRole = 'collapse-btn';
  collapseBtn.title = 'Collapse/expand';
  collapseBtn.textContent = collapsed ? '▸' : '▾';
  collapseBtn.onclick = () => {
    const s = state.steps.find((x) => x.id === step.id);
    if (!s) return;
    const now = !(s?.params?._ui_collapsed === true);
    updateStepParam(step.id, '_ui_collapsed', now);
    card.classList.toggle('ww-step-collapsed', now);
    collapseBtn.textContent = now ? '▸' : '▾';
    onChange?.();
  };

  const title = document.createElement('strong');
  title.className = 'ww-step-title';
  title.dataset.wwRole = 'step-title';
  title.textContent = `Step ${displayIndex + 1} • ${step.type}`;

  // NOTE INPUT (inline, always visible)
  const noteInp = document.createElement('input');
  noteInp.type = 'text';
  noteInp.className = 'form-control form-control-sm ww-step-note-input';
  noteInp.placeholder = 'Note (optional)…';
  noteInp.dataset.wwField = 'step-note';
  noteInp.value = String(step?.params?.note || '');
  noteInp.oninput = () => {
    updateStepParam(step.id, 'note', String(noteInp.value || ''));
    onChange?.();
  };

  left.appendChild(grip);
  left.appendChild(collapseBtn);
  left.appendChild(title);
  left.appendChild(noteInp);

  if (!isAllowed) {
    const badge = document.createElement('span');
    badge.className = 'ww-step-badge';
    badge.textContent = 'Not allowed for this event';
    left.appendChild(badge);
  }

  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'btn-close';
  rm.dataset.wwField = 'remove-step';
  rm.onclick = () => {
    removeStep(step.id);
    const old = _stepCardMap.get(step.id);
    if (old) {
      try { old.remove(); } catch {}
      _stepCardMap.delete(step.id);
    }

    state.steps.forEach((s, idx) => {
      const node = _stepCardMap.get(s.id);
      const t = node?.querySelector?.('[data-ww-role="step-title"]');
      if (t) t.textContent = `Step ${idx + 1} • ${s.type}`;
    });

    onChange?.();
    bindStepsDnD(containerEl, onChange, _stepCardMap);
  };

  header.appendChild(left);
  header.appendChild(rm);
  card.appendChild(header);

  if (!isAllowed) {
    const note = document.createElement('div');
    note.className = 'ww-step-note';
    note.textContent = 'This step type is not allowed for the currently selected event. Change the event, or remove/replace this step.';
    card.appendChild(note);
  }

  const body = document.createElement('div');
  body.className = 'ww-step-body';

  const sel = document.createElement('select');
  sel.className = 'form-select form-select-sm mb-2';
  sel.dataset.wwField = 'step-type';

  const options = [...allowedTypes];
  if (!allowedSet.has(step.type) && !options.includes(step.type) && allTypes.includes(step.type)) {
    options.unshift(step.type);
  }

  options.forEach((t) => {
    const opt = new Option(t, t);
    if (!allowedSet.has(t)) opt.disabled = true;
    sel.add(opt);
  });

  if (!allTypes.includes(step.type)) {
    const opt = new Option(step.type, step.type);
    opt.disabled = true;
    sel.add(opt, 0);
  }

  sel.value = step.type;

  const paramsDiv = document.createElement('div');

  sel.onchange = () => {
    if (!allowedSet.has(sel.value)) {
      sel.value = step.type;
      return;
    }

    updateStepType(step.id, sel.value);
    setStepParamsToDefaults(step.id, sel.value);

    const idx = state.steps.findIndex((s) => s.id === step.id);
    const updatedStep = state.steps[idx];
    if (!updatedStep) return;

    const newCard = stepCard(updatedStep, idx, { containerEl, onChange });

    const oldCard = _stepCardMap.get(step.id);
    if (oldCard && oldCard.isConnected) oldCard.replaceWith(newCard);
    else containerEl.appendChild(newCard);

    _stepCardMap.set(step.id, newCard);

    state.steps.forEach((s, i) => {
      const node = _stepCardMap.get(s.id);
      const t = node?.querySelector?.('[data-ww-role="step-title"]');
      if (t) t.textContent = `Step ${i + 1} • ${s.type}`;
    });

    onChange?.();
    bindStepsDnD(containerEl, onChange, _stepCardMap);
  };

  body.appendChild(sel);
  body.appendChild(paramsDiv);
  card.appendChild(body);

  const exec = getExecutor(step.type);
  if (exec?.renderParams) {
    exec.renderParams(paramsDiv, step, {
      updateStepParam,
      onChange,
      rerender: () => {
        const idx = state.steps.findIndex((s) => s.id === step.id);
        const refreshed = state.steps[idx];
        if (!refreshed) return;
        const newCard = stepCard(refreshed, idx, { containerEl, onChange });
        const oldCard = _stepCardMap.get(step.id);
        if (oldCard && oldCard.isConnected) oldCard.replaceWith(newCard);
        else containerEl.appendChild(newCard);
        _stepCardMap.set(step.id, newCard);
        bindStepsDnD(containerEl, onChange, _stepCardMap);
      },
    });
  }

  return card;
}
