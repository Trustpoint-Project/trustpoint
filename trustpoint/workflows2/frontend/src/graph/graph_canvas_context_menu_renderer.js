import { escapeHtml } from '../core/dom.js';

function clamp(value, min, max) {
  return Math.max(min, Math.min(value, max));
}

export function renderCanvasContextMenu({
  catalog,
  position,
  canvasWidth,
  canvasHeight,
}) {
  const left = clamp(
    Math.round(position?.x ?? 24),
    8,
    Math.max(8, (canvasWidth || 320) - 292),
  );

  const top = clamp(
    Math.round(position?.y ?? 24),
    8,
    Math.max(8, (canvasHeight || 240) - 380),
  );

  const stepButtons = (catalog?.steps || [])
    .map(
      (step) => `
        <button
          type="button"
          class="btn btn-sm btn-outline-primary text-start"
          data-graph-overlay-action="context-add-step"
          data-step-type="${escapeHtml(step.type)}"
        >
          ${escapeHtml(step.title || step.type)}
        </button>
      `,
    )
    .join('');

  return `
    <div
      class="wf2-graph-floating-card wf2-graph-context-menu"
      style="left:${left}px; top:${top}px; width:280px;"
    >
      <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
        <div class="wf2-graph-floating-title">Add step here</div>
        <button
          type="button"
          class="btn btn-sm btn-outline-secondary"
          data-graph-overlay-action="close-canvas-menu"
          aria-label="Close"
          title="Close"
        >
          ×
        </button>
      </div>

      <div class="small text-muted mb-3">
        The new step will be placed at this cursor position.
      </div>

      <div class="d-grid gap-2">
        ${stepButtons || '<div class="text-muted">No step types available.</div>'}
      </div>
    </div>
  `;
}