import { attachGraphCanvasInteractions } from './graph_canvas_interactions.js';
import { reconcileGraphNodePositions } from './graph_position_session.js';
import { debounce } from './graph_preview_http.js';
import { normalizeGraph } from './graph_preview_model.js';
import { buildGraphLayout } from './graph_preview_layout.js';
import { parseDraftWorkflowGraph } from './draft_workflow_graph_parser.js';
import { handleGraphAction } from './preview_overlay_actions.js';
import { createGraphPreviewState, snapshotStepDataById } from './preview_helpers.js';
import {
  createInteractionCallbacks,
  deleteCurrentSelection,
} from './preview_interaction_actions.js';
import { createGraphPreviewView, renderGraphPreview, renderToolbar } from './preview_view.js';

function setStatus(statusEl, value) {
  if (statusEl) {
    statusEl.textContent = value;
  }
}

export function createDraftGraphPreview({ mount, statusEl, catalog, callbacks }) {
  const state = createGraphPreviewState(catalog);
  const refs = createGraphPreviewView({ mount });

  function render() {
    renderGraphPreview(refs, state);
  }

  renderToolbar(refs, state.catalog);
  render();

  const interactions = attachGraphCanvasInteractions({
    canvasEl: refs.canvas,
    getLayout: () => state.layout,
    ...createInteractionCallbacks(state, render, callbacks),
  });

  const rerenderOverlay = () => {
    if (state.editorNodeId || state.editorEdgeId || state.canvasMenuPos) {
      render();
    }
  };

  refs.canvasWrap?.addEventListener('scroll', rerenderOverlay, { passive: true });
  window.addEventListener('resize', rerenderOverlay);

  mount.addEventListener('click', async (event) => {
    const actionEl = event.target.closest('[data-graph-action], [data-graph-overlay-action]');
    if (!actionEl) {
      return;
    }

    const action =
      actionEl.getAttribute('data-graph-overlay-action') ||
      actionEl.getAttribute('data-graph-action');
    const scope = actionEl.closest('.wf2-graph-floating-card') || mount;

    try {
      await handleGraphAction({
        action,
        actionEl,
        scope,
        refs,
        state,
        callbacks,
        render,
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setStatus(statusEl, message);
      callbacks?.onIssue?.({ level: 'error', message });
    }
  });

  async function refresh(yamlText) {
    const seq = ++state.refreshSeq;

    if (!String(yamlText || '').trim()) {
      state.graph = null;
      state.lastError = null;
      state.nodePositions = {};
      state.stepDataById = {};
      state.selectedNodeId = null;
      state.selectedEdgeId = null;
      state.editorNodeId = null;
      state.editorEdgeId = null;
      state.canvasMenuPos = null;
      callbacks?.onIssues?.([]);
      setStatus(statusEl, 'Empty');
      render();
      return;
    }

    try {
      const result = parseDraftWorkflowGraph(yamlText);
      if (seq !== state.refreshSeq) {
        return;
      }

      state.graph = result.graph;
      state.stepDataById = snapshotStepDataById(yamlText);
      callbacks?.onIssues?.(result.issues || []);

      const normalizedGraph = normalizeGraph(result.graph);
      state.nodePositions = reconcileGraphNodePositions(
        normalizedGraph,
        state.nodePositions,
        buildGraphLayout,
      );

      const currentIds = new Set((normalizedGraph?.nodes || []).map((node) => node.id));
      Object.keys(state.nodePositions).forEach((nodeId) => {
        if (!currentIds.has(nodeId)) {
          delete state.nodePositions[nodeId];
        }
      });

      const firstError = (result.issues || []).find((item) => item.level === 'error');
      state.lastError = firstError ? firstError.message : null;

      setStatus(statusEl, firstError ? 'Issues' : 'Draft');
      render();
    } catch (err) {
      if (seq !== state.refreshSeq) {
        return;
      }

      const message = err instanceof Error ? err.message : String(err);
      state.graph = null;
      state.stepDataById = {};
      state.lastError = message;
      state.selectedNodeId = null;
      state.selectedEdgeId = null;
      state.editorNodeId = null;
      state.editorEdgeId = null;
      state.canvasMenuPos = null;
      callbacks?.onIssues?.([{ level: 'error', message, offset: err?.offset ?? null }]);
      setStatus(statusEl, 'Error');
      render();
    }
  }

  return {
    setCatalog(nextCatalog) {
      state.catalog = nextCatalog;
      renderToolbar(refs, state.catalog);
      render();
    },
    refresh,
    debouncedRefresh: debounce(refresh, 250),
    async deleteSelection() {
      return deleteCurrentSelection(state, callbacks);
    },
    hasSelection() {
      return Boolean(state.selectedNodeId || state.selectedEdgeId);
    },
    closeEditor() {
      state.editorNodeId = null;
      state.editorEdgeId = null;
      state.canvasMenuPos = null;
      render();
    },
    destroy() {
      interactions.destroy();
      refs.canvasWrap?.removeEventListener('scroll', rerenderOverlay);
      window.removeEventListener('resize', rerenderOverlay);
    },
  };
}
