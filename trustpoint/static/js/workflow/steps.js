// static/js/workflow/steps.js
import {
  state, addStep, removeStep, updateStepType, updateStepParam, moveStep,
} from './state.js';
import { getTypes, get as getExecutor } from './executors/index.js';

// Side-effect imports (register executors)
import './executors/approval.js';
import './executors/email.js';
import './executors/webhook.js';
import './executors/condition.js';

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
  `;
  document.head.appendChild(style);
}

export function renderStepsUI({ containerEl, addBtnEl, onChange }) {
  injectStylesOnce();
  containerEl.textContent = '';

  const frag = document.createDocumentFragment();
  state.steps.forEach((step, idx) => frag.appendChild(stepCard(step, idx, { containerEl, addBtnEl, onChange })));
  containerEl.appendChild(frag);

  addBtnEl.onclick = () => {
    // default to Approval (or first registry type)
    const first = getTypes()[0] || 'Approval';
    addStep(first, {});
    renderStepsUI({ containerEl, addBtnEl, onChange });
    onChange();
  };

  enableDnD(containerEl, addBtnEl, onChange);
}

function stepCard(step, displayIndex, ctx) {
  const { containerEl, addBtnEl, onChange } = ctx;

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

  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'btn-close';
  rm.onclick = () => {
    removeStep(step.id);
    renderStepsUI({ containerEl, addBtnEl, onChange });
    onChange();
  };

  header.appendChild(left);
  header.appendChild(rm);
  card.appendChild(header);

  // Type selector (from registry)
  const sel = document.createElement('select');
  sel.className = 'form-select form-select-sm mb-2';
  getTypes().forEach(t => sel.add(new Option(t, t)));
  sel.value = step.type;
  sel.onchange = () => {
    updateStepType(step.id, sel.value);
    renderStepsUI({ containerEl, addBtnEl, onChange });
    onChange();
  };
  card.appendChild(sel);

  // Params area
  const paramsDiv = document.createElement('div');
  card.appendChild(paramsDiv);

  const exec = getExecutor(step.type);
  if (exec?.renderParams) {
    exec.renderParams(paramsDiv, step, {
      updateStepParam,
      onChange,
    });
  }

  return card;
}

function enableDnD(containerEl, addBtnEl, onChange) {
  let dragId = null;
  let dragCard = null;

  containerEl.querySelectorAll('.ww-drag-handle[draggable="true"]').forEach(handle => {
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
      containerEl.querySelectorAll('.ww-step-card').forEach(c => {
        c.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
      });
    };
  });

  containerEl.querySelectorAll('.ww-step-card').forEach(card => {
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
      const fromIndex = steps.findIndex(s => s.id === dragId);
      const toIndexBase = steps.findIndex(s => s.id === targetId);

      const rect = card.getBoundingClientRect();
      const before = (e.clientY - rect.top) < rect.height / 2;
      let toIndex = toIndexBase + (before ? 0 : 1);

      moveStep(dragId, toIndex > fromIndex ? toIndex - 1 : toIndex);
      renderStepsUI({ containerEl, addBtnEl, onChange });
      onChange();
    };
  });
}
