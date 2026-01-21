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
  `;
  document.head.appendChild(style);
}

/**
 * Policy: which step types are allowed for a given event selection.
 */
function allowedStepTypesForEvent({ handler, protocol, operation }, allTypes) {
  const h = String(handler || '').trim();
  if (!h) return allTypes;

  if (h === 'device_action') {
    const allowed = new Set(['Webhook', 'Email', 'Logic']);
    return allTypes.filter((t) => allowed.has(t));
  }

  if (h === 'certificate_request') {
    return allTypes;
  }

  return allTypes;
}

function eventKey() {
  return `h=${String(state.handler || '').trim()}::p=${String(state.protocol || '').trim()}::o=${String(state.operation || '').trim()}`;
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

  // Clear existing params via normal pipeline
  const s = state.steps.find((x) => x.id === stepId);
  const existing = (s && s.params && typeof s.params === 'object' && !Array.isArray(s.params))
    ? Object.keys(s.params)
    : [];

  existing.forEach((k) => updateStepParam(stepId, k, undefined));
  Object.entries(defaults).forEach(([k, v]) => updateStepParam(stepId, k, v));
}
// ------------------------

let _lastEventKey = null;
let _boundReRender = false;

// ---------- focus/scroll preservation ----------
function _focusables(root) {
  return Array.from(root.querySelectorAll('input, select, textarea, button, [tabindex]'))
    .filter((el) => {
      if (!(el instanceof HTMLElement)) return false;
      if (el.tabIndex < 0) return false;
      if (el.hasAttribute('disabled')) return false;
      if (el.getAttribute('aria-disabled') === 'true') return false;
      return true;
    });
}

function _captureUIState(containerEl) {
  const winY = window.scrollY;
  const contY = containerEl.scrollTop;

  const ae = document.activeElement;
  if (!ae || !(ae instanceof HTMLElement) || !containerEl.contains(ae)) {
    return { winY, contY, focus: null };
  }

  const card = ae.closest('.ww-step-card');
  const stepId = card ? String(card.dataset.stepId || '') : '';
  const within = card || containerEl;

  const focusables = _focusables(within);
  const focusIndex = Math.max(0, focusables.indexOf(ae));

  let selection = null;
  if (ae instanceof HTMLInputElement || ae instanceof HTMLTextAreaElement) {
    try {
      selection = { start: ae.selectionStart, end: ae.selectionEnd };
    } catch {
      selection = null;
    }
  }

  return { winY, contY, focus: { stepId, focusIndex, selection } };
}

function _restoreUIState(containerEl, snap) {
  if (!snap) return;

  // restore scroll first (prevents browser from choosing a new anchor)
  try { window.scrollTo(0, snap.winY); } catch {}
  try { containerEl.scrollTop = snap.contY; } catch {}

  const f = snap.focus;
  if (!f) return;

  const card = f.stepId
    ? containerEl.querySelector(`.ww-step-card[data-step-id="${CSS.escape(f.stepId)}"]`)
    : null;

  const within = card || containerEl;
  const focusables = _focusables(within);
  const target = focusables[f.focusIndex] || null;

  if (target) {
    try { target.focus({ preventScroll: true }); } catch { try { target.focus(); } catch {} }
    if (f.selection && (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement)) {
      try { target.setSelectionRange(f.selection.start ?? 0, f.selection.end ?? 0); } catch {}
    }
  }

  // enforce scroll again after focus to avoid focus-induced jump
  try { window.scrollTo(0, snap.winY); } catch {}
  try { containerEl.scrollTop = snap.contY; } catch {}
}
// ---------------------------------------------

export function renderStepsUI({ containerEl, addBtnEl, onChange }) {
  injectStylesOnce();

  const rerender = () => {
    const snap = _captureUIState(containerEl);
    renderStepsUI({ containerEl, addBtnEl, onChange });
    _restoreUIState(containerEl, snap);
  };

  if (!_boundReRender) {
    _boundReRender = true;
    document.addEventListener('wf:changed', () => {
      const k = eventKey();
      if (k !== _lastEventKey) {
        _lastEventKey = k;
        rerender();
      }
    });
  }
  _lastEventKey = eventKey();

  containerEl.textContent = '';

  const { allowedTypes } = computeAllowedTypes();

  if (!allowedTypes.length) {
    addBtnEl.disabled = true;
    addBtnEl.title = 'No step types available for this event selection.';
  } else {
    addBtnEl.disabled = false;
    addBtnEl.title = '';
  }

  const frag = document.createDocumentFragment();
  state.steps.forEach((step, idx) => frag.appendChild(stepCard(step, idx, { containerEl, addBtnEl, onChange, rerender })));
  containerEl.appendChild(frag);

  addBtnEl.onclick = () => {
    const snap = _captureUIState(containerEl);

    const { allowedTypes: allowedNow } = computeAllowedTypes();
    const firstAllowed = allowedNow[0];
    if (!firstAllowed) return;

    addStep(firstAllowed, getDefaultParamsForType(firstAllowed));

    // Render + restore scroll/focus near where user was
    renderStepsUI({ containerEl, addBtnEl, onChange });
    _restoreUIState(containerEl, snap);
    onChange();
  };

  enableDnD(containerEl, addBtnEl, onChange, rerender);
}

function stepCard(step, displayIndex, ctx) {
  const { onChange, rerender } = ctx;
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
  rm.onclick = () => {
    removeStep(step.id);
    rerender();
    onChange();
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

  sel.onchange = () => {
    if (!allowedSet.has(sel.value)) {
      sel.value = step.type;
      return;
    }

    updateStepType(step.id, sel.value);
    setStepParamsToDefaults(step.id, sel.value);

    rerender();
    onChange();
  };

  card.appendChild(sel);

  const paramsDiv = document.createElement('div');
  card.appendChild(paramsDiv);

  const exec = getExecutor(step.type);
  if (exec?.renderParams) {
    exec.renderParams(paramsDiv, step, {
      updateStepParam,
      onChange,
      rerender,
    });
  }

  return card;
}

function enableDnD(containerEl, addBtnEl, onChange, rerender) {
  let dragId = null;
  let dragCard = null;

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
      rerender();
      onChange();
    };
  });
}
