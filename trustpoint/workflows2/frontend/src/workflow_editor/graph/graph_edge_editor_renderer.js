import { escapeHtml } from '../shared/dom.js';
import { fitPanelToViewport, placePanelNearPoint } from './graph_overlay_position.js';

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
  viewport,
  edge,
}) {
  const anchor = buildEdgeAnchor(layout, edge);
  if (!anchor) {
    return '';
  }

  const fitted = fitPanelToViewport(viewport, {
    panelWidth: 420,
    panelHeight: edge.on ? 300 : 230,
    minWidth: 320,
    minHeight: 220,
  });
  const { left, top } = placePanelNearPoint(viewport, anchor, {
    panelWidth: fitted.width,
    panelHeight: fitted.height,
  });

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-edge wf2-graph-overlay-shell" style="left:${left}px; top:${top}px; width:${fitted.width}px; max-width:${fitted.maxWidth}px; max-height:${fitted.maxHeight}px;">
      <div class="wf2-graph-floating-header">
        <div>
          <div class="wf2-graph-floating-kicker">Edge editor</div>
          <div class="wf2-graph-floating-title">
            <code>${escapeHtml(edge.from)}</code> → <code>${escapeHtml(edge.to)}</code>
          </div>
          <div class="wf2-graph-floating-subtitle">
            ${edge.on ? 'Outcome transition' : 'Linear transition'}
          </div>
        </div>
        ${renderCloseButton()}
      </div>

      <div class="wf2-graph-floating-meta">
        <span class="wf2-graph-meta-pill"><span>From</span><strong>${escapeHtml(edge.from)}</strong></span>
        <span class="wf2-graph-meta-pill"><span>To</span><strong>${escapeHtml(edge.to)}</strong></span>
        <span class="wf2-graph-meta-pill"><span>Mode</span><strong>${escapeHtml(edge.on || 'linear')}</strong></span>
      </div>

      <div class="wf2-graph-floating-body">
        ${
          edge.on
            ? `
              <section class="wf2-graph-editor-section">
                <div class="wf2-graph-editor-section-title">Outcome</div>
                <div class="wf2-graph-editor-inline-row">
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
              </section>
            `
            : `
              <section class="wf2-graph-editor-section">
                <div class="wf2-graph-editor-section-title">Transition mode</div>
                <div class="small text-muted">
                  This edge runs automatically after the source step completes.
                </div>
              </section>
            `
        }
      </div>

      <div class="wf2-graph-floating-footer">
        <button
          type="button"
          class="btn btn-sm btn-outline-danger"
          data-graph-overlay-action="delete-edge"
          data-edge-id="${escapeHtml(edge.id)}"
        >
          Delete edge
        </button>
      </div>
    </div>
  `;
}
