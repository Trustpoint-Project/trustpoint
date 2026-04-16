import { escapeHtml } from '../shared/dom.js';
import { fitPanelToViewport, placePanelNearPoint } from './graph_overlay_position.js';

export function renderCanvasContextMenu({
  catalog,
  position,
  viewport,
}) {
  const fitted = fitPanelToViewport(viewport, {
    panelWidth: 340,
    panelHeight: 500,
    minWidth: 300,
    minHeight: 240,
  });
  const { left, top } = placePanelNearPoint(viewport, {
    x: Math.round(position?.x ?? 24),
    y: Math.round(position?.y ?? 24),
  }, {
    panelWidth: fitted.width,
    panelHeight: fitted.height,
  });

  const stepButtons = (catalog?.steps || [])
    .map(
      (step) => `
        <button
          type="button"
          class="wf2-graph-step-pick"
          data-graph-overlay-action="context-add-step"
          data-step-type="${escapeHtml(step.type)}"
        >
          <span class="wf2-graph-step-pick-title">${escapeHtml(step.title || step.type)}</span>
          <span class="wf2-graph-step-pick-meta">${escapeHtml(step.type)}</span>
          <span class="wf2-graph-step-pick-desc">${escapeHtml(step.description || 'Add this step at the clicked canvas position.')}</span>
        </button>
      `,
    )
    .join('');

  return `
    <div
      class="wf2-graph-floating-card wf2-graph-context-menu wf2-graph-overlay-shell"
      style="left:${left}px; top:${top}px; width:${fitted.width}px; max-width:${fitted.maxWidth}px; max-height:${fitted.maxHeight}px;"
    >
      <div class="wf2-graph-floating-header">
        <div>
          <div class="wf2-graph-floating-kicker">Canvas menu</div>
          <div class="wf2-graph-floating-title">Add step here</div>
          <div class="wf2-graph-floating-subtitle">The new step will be placed near the cursor position you clicked.</div>
        </div>
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

      <div class="wf2-graph-floating-body">
        <div class="wf2-graph-editor-section">
          <div class="wf2-graph-editor-section-title">Available step types</div>
          <div class="wf2-graph-step-pick-grid">
            ${stepButtons || '<div class="text-muted">No step types available.</div>'}
          </div>
        </div>
      </div>
    </div>
  `;
}
