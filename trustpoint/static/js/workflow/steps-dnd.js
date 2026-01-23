// static/js/workflow/steps-dnd.js
import { state, moveStep } from './state.js';

/**
 * Bind drag & drop handlers for step cards.
 * This function is idempotent: calling it again replaces handlers.
 */
export function bindStepsDnD(containerEl, onChange, stepCardMap) {
  if (!containerEl) return;

  let dragId = null;
  let dragCard = null;

  const clearDropIndicators = () => {
    containerEl.querySelectorAll('.ww-step-card').forEach((c) => {
      c.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
    });
  };

  const clearDragging = () => {
    if (dragCard && dragCard.isConnected) dragCard.classList.remove('ww-dragging');
    dragCard = null;
    dragId = null;
    clearDropIndicators();
  };

  // Safety: if a drag is cancelled or ends outside expected targets, ensure cleanup.
  // (Some browsers do not reliably fire dragend on the handle.)
  const bindGlobalCleanup = () => {
    // replace any previous handlers by overwriting
    document.onmouseup = () => clearDragging();
    window.onblur = () => clearDragging();
    document.ondragend = () => clearDragging();
    document.ondrop = () => clearDragging();
  };
  bindGlobalCleanup();

  // Handles
  containerEl.querySelectorAll('.ww-drag-handle[draggable="true"]').forEach((handle) => {
    handle.ondragstart = (e) => {
      const card = handle.closest('.ww-step-card');
      if (!card) return;

      dragId = Number(card.dataset.stepId);
      dragCard = card;

      // Ensure no stale drag styles remain anywhere.
      containerEl.querySelectorAll('.ww-step-card.ww-dragging').forEach((c) => c.classList.remove('ww-dragging'));
      card.classList.add('ww-dragging');

      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', String(dragId)); } catch {}
      try { e.dataTransfer.setDragImage(card, 10, 10); } catch {}
    };

    // Keep it, but do not rely on it alone.
    handle.ondragend = () => {
      clearDragging();
    };
  });

  // Cards
  containerEl.querySelectorAll('.ww-step-card').forEach((card) => {
    // Critical: ensure dragend on the CARD always clears the outline.
    card.ondragend = () => {
      clearDragging();
    };

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

      if (!dragId) {
        clearDragging();
        return;
      }

      const targetId = Number(card.dataset.stepId);
      if (dragId === targetId) {
        clearDragging();
        return;
      }

      const steps = state.steps;
      const fromIndex = steps.findIndex((s) => s.id === dragId);
      const toIndexBase = steps.findIndex((s) => s.id === targetId);

      if (fromIndex < 0 || toIndexBase < 0) {
        clearDragging();
        return;
      }

      const rect = card.getBoundingClientRect();
      const before = (e.clientY - rect.top) < rect.height / 2;
      let toIndex = toIndexBase + (before ? 0 : 1);

      moveStep(dragId, toIndex > fromIndex ? toIndex - 1 : toIndex);

      // Reorder DOM to match state without rebuilding
      const frag = document.createDocumentFragment();
      state.steps.forEach((s, idx) => {
        const node = stepCardMap?.get?.(s.id);
        if (!node) return;

        const t = node.querySelector?.('[data-ww-role="step-title"]');
        if (t) t.textContent = `Step ${idx + 1} • ${s.type}`;

        frag.appendChild(node);
      });

      containerEl.appendChild(frag);

      // Cleanup must happen even if DOM moved
      clearDragging();

      onChange?.();
      bindStepsDnD(containerEl, onChange, stepCardMap);
    };
  });
}
