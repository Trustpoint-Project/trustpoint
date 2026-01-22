// static/js/workflow/steps.js
import {
  state, addStep, removeStep, updateStepType, updateStepParam, moveStep,
} from './state.js';
import { getTypes, get as getExecutor } from './executors/index.js';

// Side-effect imports (register executors)
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
    /* Visuals */
    .ww-step-card { border-radius:.6rem; border:1px solid var(--bs-border-color,#dee2e6); }
    .ww-step-header { border-radius:.5rem; padding:.5rem .75rem; }
    .ww-drag-handle { cursor: grab; user-select:none; font-size:1.1rem; opacity:.7; }
    .ww-dragging { opacity:.6; }
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

    /* CRITICAL: disable browser scroll anchoring inside steps.
       Prevents viewport jumps when cards above change height. */
    #steps-list, .ww-step-card, .ww-step-card * {
      overflow-anchor: none;
    }
  `;
  document.head.appendChild(style);
}

/**
 * Policy: which step types are allowed for a given event selection.
 */
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

// ---- DEFAULT PARAMS ----
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

  // Remove existing keys
  Object.keys(s.params).forEach((k) => { delete s.params[k]; });

  // Apply defaults (via your state helper to keep behavior consistent)
  Object.entries(defaults).forEach(([k, v]) => updateStepParam(stepId, k, v));
}
// ------------------------

// ---------- INCREMENTAL RENDERING (fixes jumping) ----------
const _stepCardMap = new Map(); // stepId -> HTMLElement

function _clearStepDomCache() {
  _stepCardMap.clear();
}
// ---------------------------------------------------------

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

  // If the container was replaced (navigation / template), reset cache.
  // Also reset cache if container is empty but we think we have cards.
  if (!_stepCardMap.size && containerEl.children.length === 0) {
    // ok
  } else if (_stepCardMap.size && containerEl.children.length === 0) {
    _clearStepDomCache();
  }

  // --- Incremental mount/update ---
  const seen = new Set();

  state.steps.forEach((step, idx) => {
    if (!step) return;
    seen.add(step.id);

    const existing = _stepCardMap.get(step.id);
    if (existing && existing.isConnected) {
      // Update display index + title without rebuilding
      const title = existing.querySelector('[data-ww-role="step-title"]');
      if (title) title.textContent = `Step ${idx + 1} • ${step.type}`;
      return;
    }

    const card = stepCard(step, idx, { containerEl, onChange });
    _stepCardMap.set(step.id, card);
    containerEl.appendChild(card);
  });

  // Remove DOM nodes for deleted steps
  for (const [id, node] of Array.from(_stepCardMap.entries())) {
    if (!seen.has(id)) {
      try { node.remove(); } catch {}
      _stepCardMap.delete(id);
    }
  }

  // Add step (append only, no full rebuild)
  addBtnEl.onclick = () => {
    const { allowedTypes: allowedNow } = computeAllowedTypes();
    const firstAllowed = allowedNow[0];
    if (!firstAllowed) return;

    addStep(firstAllowed, getDefaultParamsForType(firstAllowed));

    // The new step is the last one in state.steps
    const step = state.steps[state.steps.length - 1];
    if (!step) return;

    const card = stepCard(step, state.steps.length - 1, { containerEl, onChange });
    _stepCardMap.set(step.id, card);
    containerEl.appendChild(card);

    onChange?.();
    enableDnD(containerEl, onChange); // re-bind DnD handlers for new card
  };

  enableDnD(containerEl, onChange);
}

function stepCard(step, displayIndex, ctx) {
  const { onChange, containerEl } = ctx;
  const { allTypes, allowedTypes, allowedSet } = computeAllowedTypes();

  const isAllowed = allowedSet.has(step.type);

  const card = document.createElement('div');
  card.className = 'card ww-step-card mb-2 p-2';
  card.dataset.stepId = String(step.id);

  const header = document.createElement('div');
  header.className = 'ww-step-header d-flex justify-content-between align-items-center mb-2';

  const left = document.createElement('div');
  left.className = 'd-flex align-items-center gap-2';

  const grip = document.createElement('span');
  grip.className = 'ww-drag-handle';
  grip.title = 'Drag to reorder';
  grip.textContent = '⋮⋮';
  grip.setAttribute('draggable', 'true');

  const title = document.createElement('strong');
  title.dataset.wwRole = 'step-title';
  title.textContent = `Step ${displayIndex + 1} • ${step.type}`;

  left.appendChild(grip);
  left.appendChild(title);

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

    // Re-label titles after removal
    state.steps.forEach((s, idx) => {
      const node = _stepCardMap.get(s.id);
      const t = node?.querySelector?.('[data-ww-role="step-title"]');
      if (t) t.textContent = `Step ${idx + 1} • ${s.type}`;
    });

    onChange?.();
    enableDnD(containerEl, onChange);
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

  // Replace only THIS card on type change (no global rerender -> no jumping)
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
    if (oldCard && oldCard.isConnected) {
      oldCard.replaceWith(newCard);
    } else {
      containerEl.appendChild(newCard);
    }
    _stepCardMap.set(step.id, newCard);

    // Re-label titles (in case ordering changed elsewhere)
    state.steps.forEach((s, i) => {
      const node = _stepCardMap.get(s.id);
      const t = node?.querySelector?.('[data-ww-role="step-title"]');
      if (t) t.textContent = `Step ${i + 1} • ${s.type}`;
    });

    onChange?.();
    enableDnD(containerEl, onChange);
  };

  card.appendChild(sel);
  card.appendChild(paramsDiv);

  const exec = getExecutor(step.type);
  if (exec?.renderParams) {
    exec.renderParams(paramsDiv, step, {
      updateStepParam,
      onChange,
      // Keep rerender available for executors that call it; implement as local replace:
      rerender: () => {
        const idx = state.steps.findIndex((s) => s.id === step.id);
        const refreshed = state.steps[idx];
        if (!refreshed) return;
        const newCard = stepCard(refreshed, idx, { containerEl, onChange });
        const oldCard = _stepCardMap.get(step.id);
        if (oldCard && oldCard.isConnected) oldCard.replaceWith(newCard);
        else containerEl.appendChild(newCard);
        _stepCardMap.set(step.id, newCard);
        enableDnD(containerEl, onChange);
      },
    });
  }

  return card;
}

function enableDnD(containerEl, onChange) {
  if (!containerEl) return;

  let dragId = null;
  let dragCard = null;

  // Bind handles
  containerEl.querySelectorAll('.ww-drag-handle[draggable="true"]').forEach((handle) => {
    handle.ondragstart = (e) => {
      const card = handle.closest('.ww-step-card');
      if (!card) return;
      dragId = Number(card.dataset.stepId);
      dragCard = card;
      card.classList.add('ww-dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', String(dragId)); } catch {}
      try { e.dataTransfer.setDragImage(card, 10, 10); } catch {}
    };
    handle.ondragend = () => {
      if (dragCard) dragCard.classList.remove('ww-dragging');
      dragId = null;
      dragCard = null;
      containerEl.querySelectorAll('.ww-step-card').forEach((c) => {
        c.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
      });
    };
  });

  containerEl.querySelectorAll('.ww-step-card').forEach((card) => {
    card.ondragover = (e) => {
      if (!dragId) return;
      e.preventDefault();
      const rect = card.getBoundingClientRect();
      const before = (e.clientY - rect.top) < rect.height / 2;
      card.classList.toggle('ww-drop-indicator-top', before);
      card.classList.toggle('ww-drop-indicator-bottom', !before);
    };
    card.ondragleave = () => {
      card.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
    };
    card.ondrop = (e) => {
      e.preventDefault();
      card.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
      if (!dragId) return;

      const targetId = Number(card.dataset.stepId);
      if (dragId === targetId) return;

      const steps = state.steps;
      const fromIndex = steps.findIndex((s) => s.id === dragId);
      const toIndexBase = steps.findIndex((s) => s.id === targetId);

      const rect = card.getBoundingClientRect();
      const before = (e.clientY - rect.top) < rect.height / 2;
      let toIndex = toIndexBase + (before ? 0 : 1);

      moveStep(dragId, toIndex > fromIndex ? toIndex - 1 : toIndex);

      // Reorder DOM to match state without rebuilding
      // (detach + append in state order)
      const frag = document.createDocumentFragment();
      state.steps.forEach((s, idx) => {
        const node = _stepCardMap.get(s.id);
        if (!node) return;

        const t = node.querySelector?.('[data-ww-role="step-title"]');
        if (t) t.textContent = `Step ${idx + 1} • ${s.type}`;

        frag.appendChild(node);
      });

      // Append fragment (moves existing nodes; does not recreate)
      containerEl.appendChild(frag);

      onChange?.();
      enableDnD(containerEl, onChange);
    };
  });
}
