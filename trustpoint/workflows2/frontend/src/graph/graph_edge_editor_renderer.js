import { escapeHtml } from '../core/dom.js';

function clamp(value, min, max) {
  return Math.max(min, Math.min(value, max));
}

function buildEdgeAnchor(layout, edge) {
  const from = layout.positions.get(edge.from);
  const to = layout.positions.get(edge.to);

  if (!from || !to) {
    return null;
  }

  const x1 = from.x + from.w;
  const y1 = from.y + from.h / 2;
  const x2 = to.x;
  const y2 = to.y + to.h / 2;

  return {
    x: (x1 + x2) / 2,
    y: (y1 + y2) / 2,
  };
}

function renderCloseButton() {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-secondary"
      data-graph-overlay-action="close-editor"
      aria-label="Close"
      title="Close"
    >
      ×
    </button>
  `;
}

export function renderGraphEdgeEditorOverlay({
  layout,
  edge,
}) {
  const anchor = buildEdgeAnchor(layout, edge);
  if (!anchor) {
    return '';
  }

  const left = clamp(anchor.x + 12, 8, layout.width - 292);
  const top = clamp(anchor.y - 20, 8, layout.height - 220);

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-edge" style="left:${left}px; top:${top}px;">
      <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
        <div class="wf2-graph-floating-title">
          Edge: <code>${escapeHtml(edge.from)}</code> → <code>${escapeHtml(edge.to)}</code>
        </div>
        ${renderCloseButton()}
      </div>

      ${
        edge.on
          ? `
            <div class="mb-2">
              <label class="form-label form-label-sm mb-1">Outcome</label>
              <div class="d-flex gap-2">
                <input
                  type="text"
                  class="form-control form-control-sm"
                  data-edge-outcome-input="true"
                  value="${escapeHtml(edge.on)}"
                >
                <button
                  type="button"
                  class="btn btn-sm btn-outline-primary"
                  data-graph-overlay-action="rename-edge-outcome"
                  data-edge-id="${escapeHtml(edge.id)}"
                >
                  Save
                </button>
              </div>
            </div>
          `
          : `
            <div class="small text-muted mb-3">
              Linear edge
            </div>
          `
      }

      <button
        type="button"
        class="btn btn-sm btn-outline-danger"
        data-graph-overlay-action="delete-edge"
        data-edge-id="${escapeHtml(edge.id)}"
      >
        Delete edge
      </button>
    </div>
  `;
}