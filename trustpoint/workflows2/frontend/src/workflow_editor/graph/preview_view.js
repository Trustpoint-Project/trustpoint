import { buildGraphLayout } from './graph_preview_layout.js';
import { renderCanvasContextMenu } from './graph_canvas_context_menu_renderer.js';
import { renderGraphFloatingEditor } from './graph_floating_editor_renderer.js';
import { measureOverlayViewport } from './graph_overlay_position.js';
import {
  renderGraphNotice,
  renderGraphToolbarOptions,
} from './graph_preview_inspector_renderer.js';
import { normalizeGraph } from './graph_preview_model.js';
import { renderGraphSvg } from './graph_preview_svg_renderer.js';
import {
  freezeMissingNodePositions,
  getOverlayStateKey,
  readOverlayScroll,
  restoreOverlayScroll,
} from './preview_helpers.js';

function renderEmptyState(refs, message) {
  refs.canvas.innerHTML = `<div class="wf2-graph-canvas-empty-state">${message}</div>`;
}

function clearMissingIds(state, graph) {
  const nodeIds = new Set(graph.nodes.map((node) => node.id));
  const edgeIds = new Set(graph.edges.map((edge) => edge.id));

  if (state.selectedNodeId && !nodeIds.has(state.selectedNodeId)) {
    state.selectedNodeId = null;
  }
  if (state.selectedEdgeId && !edgeIds.has(state.selectedEdgeId)) {
    state.selectedEdgeId = null;
  }
  if (state.editorNodeId && !nodeIds.has(state.editorNodeId)) {
    state.editorNodeId = null;
  }
  if (state.editorEdgeId && !edgeIds.has(state.editorEdgeId)) {
    state.editorEdgeId = null;
  }
}

export function createGraphPreviewView({ mount }) {
  mount.innerHTML = `
    <div class="wf2-graph-ui">
      <div class="wf2-graph-toolbar">
        <label class="small text-muted mb-0" for="wf2-graph-add-step-select">Add step</label>
        <select class="form-select form-select-sm" id="wf2-graph-add-step-select"></select>
        <button class="btn btn-sm btn-primary" data-graph-action="add-step">Add</button>
      </div>

      <div id="wf2-graph-notice"></div>

      <div class="wf2-graph-main">
        <div class="wf2-graph-canvas-wrap">
          <div id="wf2-graph-canvas" class="wf2-graph-canvas"></div>
        </div>
        <div id="wf2-graph-overlay-root" class="wf2-graph-overlay-root"></div>
      </div>
    </div>
  `;

  return {
    addStepSelect: mount.querySelector('#wf2-graph-add-step-select'),
    canvasWrap: mount.querySelector('.wf2-graph-canvas-wrap'),
    canvas: mount.querySelector('#wf2-graph-canvas'),
    overlay: mount.querySelector('#wf2-graph-overlay-root'),
    notice: mount.querySelector('#wf2-graph-notice'),
  };
}

export function renderToolbar(refs, catalog) {
  refs.addStepSelect.innerHTML = renderGraphToolbarOptions(catalog);
}

export function renderGraphPreview(refs, state) {
  const previousOverlayKey = state.overlayScrollKey;
  if (previousOverlayKey) {
    state.overlayScroll = readOverlayScroll(refs.overlay);
  }

  refs.notice.innerHTML = renderGraphNotice(state.lastError);

  if (!state.graph) {
    state.normalizedGraph = null;
    state.layout = null;
    renderEmptyState(refs, 'No graph available yet.');
    if (refs.overlay) {
      refs.overlay.innerHTML = '';
    }
    state.overlayScrollKey = null;
    state.overlayScroll = null;
    return;
  }

  const graph = normalizeGraph(state.graph);
  state.nodePositions = freezeMissingNodePositions(graph, state.nodePositions);
  state.layout = buildGraphLayout(graph, state.nodePositions);
  state.normalizedGraph = graph;
  clearMissingIds(state, graph);
  const viewport = measureOverlayViewport(refs.canvasWrap);

  refs.canvas.innerHTML = `
    <div class="wf2-graph-canvas-stage">
      ${renderGraphSvg(
        graph,
        state.layout,
        state.selectedNodeId,
        state.selectedEdgeId,
        state.connectPreview,
        state.dragNodeId,
      )}
    </div>
  `;

  renderGraphFloatingEditor({
    rootEl: refs.overlay,
    graph,
    layout: state.layout,
    viewport,
    catalog: state.catalog,
    openNodeId: state.editorNodeId,
    openEdgeId: state.editorEdgeId,
    stepDataById: state.stepDataById,
  });

  if (state.canvasMenuPos) {
    refs.overlay.insertAdjacentHTML(
      'beforeend',
      renderCanvasContextMenu({
        catalog: state.catalog,
        position: state.canvasMenuPos,
        viewport,
      }),
    );
  }

  const nextOverlayKey = getOverlayStateKey(state);
  if (nextOverlayKey && nextOverlayKey === previousOverlayKey && state.overlayScroll) {
    restoreOverlayScroll(refs.overlay, state.overlayScroll);
  } else if (nextOverlayKey !== previousOverlayKey) {
    state.overlayScroll = null;
  }

  state.overlayScrollKey = nextOverlayKey;
}
