import { debounce } from './graph_preview_http.js';
import { normalizeGraph } from './graph_preview_model.js';
import { buildGraphLayout } from './graph_preview_layout.js';
import { renderGraphSvg } from './graph_preview_svg_renderer.js';
import {
  renderGraphInspector,
  renderGraphNotice,
  renderGraphToolbarOptions,
} from './graph_preview_inspector_renderer.js';
import { parseDraftWorkflowGraph } from './draft_workflow_graph_parser.js';

export function createDraftGraphPreview({
  mount,
  statusEl,
  catalog,
  callbacks,
}) {
  const state = {
    graph: null,
    catalog: catalog || null,
    selectedNodeId: null,
    selectedEdgeId: null,
    refreshSeq: 0,
    lastError: null,
  };

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
          <div id="wf2-graph-canvas" class="wf2-graph-canvas-empty">Loading graph…</div>
        </div>
        <aside id="wf2-graph-inspector" class="wf2-graph-inspector"></aside>
      </div>
    </div>
  `;

  const refs = {
    addStepSelect: mount.querySelector('#wf2-graph-add-step-select'),
    canvas: mount.querySelector('#wf2-graph-canvas'),
    inspector: mount.querySelector('#wf2-graph-inspector'),
    notice: mount.querySelector('#wf2-graph-notice'),
  };

  function setStatus(value) {
    if (statusEl) {
      statusEl.textContent = value;
    }
  }

  function renderToolbar() {
    refs.addStepSelect.innerHTML = renderGraphToolbarOptions(state.catalog);
  }

  function render() {
    refs.notice.innerHTML = renderGraphNotice(state.lastError);

    if (!state.graph) {
      refs.canvas.innerHTML = '<div class="wf2-graph-canvas-empty">No graph available yet.</div>';
      refs.inspector.innerHTML = renderGraphInspector(null, state.catalog, null, null);
      return;
    }

    const graph = normalizeGraph(state.graph);

    const nodeIds = new Set(graph.nodes.map((node) => node.id));
    const edgeIds = new Set(graph.edges.map((edge) => edge.id));

    if (state.selectedNodeId && !nodeIds.has(state.selectedNodeId)) {
      state.selectedNodeId = null;
    }
    if (state.selectedEdgeId && !edgeIds.has(state.selectedEdgeId)) {
      state.selectedEdgeId = null;
    }

    const layout = buildGraphLayout(graph);
    refs.canvas.innerHTML = renderGraphSvg(
      graph,
      layout,
      state.selectedNodeId,
      state.selectedEdgeId,
    );
    refs.inspector.innerHTML = renderGraphInspector(
      graph,
      state.catalog,
      state.selectedNodeId,
      state.selectedEdgeId,
    );
  }

  refs.canvas.addEventListener('click', (event) => {
    const nodeEl = event.target.closest('[data-node-id]');
    if (nodeEl) {
      state.selectedNodeId = nodeEl.getAttribute('data-node-id');
      state.selectedEdgeId = null;
      render();
      return;
    }

    const edgeEl = event.target.closest('[data-edge-id]');
    if (edgeEl) {
      state.selectedEdgeId = edgeEl.getAttribute('data-edge-id');
      state.selectedNodeId = null;
      render();
    }
  });

  mount.addEventListener('click', async (event) => {
    const actionEl = event.target.closest('[data-graph-action]');
    if (!actionEl) {
      return;
    }

    const action = actionEl.getAttribute('data-graph-action');

    try {
      if (action === 'add-step') {
        const stepType = refs.addStepSelect.value;
        if (!stepType) {
          return;
        }
        await callbacks.onAddStep(stepType);
        return;
      }

      if (action === 'save-title') {
        const stepId = actionEl.getAttribute('data-step-id');
        const title = mount.querySelector('#wf2-graph-title-input')?.value || '';
        await callbacks.onSetTitle(stepId, title);
        return;
      }

      if (action === 'apply-type') {
        const stepId = actionEl.getAttribute('data-step-id');
        const stepType = mount.querySelector('#wf2-graph-type-select')?.value || '';
        await callbacks.onSetType(stepId, stepType);
        return;
      }

      if (action === 'set-start') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onSetStart(stepId);
        return;
      }

      if (action === 'delete-step') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onDeleteStep(stepId);
        state.selectedNodeId = null;
        return;
      }

      if (action === 'add-linear-edge') {
        const fromStep = actionEl.getAttribute('data-step-id');
        const toStep = mount.querySelector('#wf2-graph-target-select')?.value || '';
        await callbacks.onAddLinearEdge(fromStep, toStep);
        return;
      }

      if (action === 'add-outcome-edge') {
        const fromStep = actionEl.getAttribute('data-step-id');
        const toStep = mount.querySelector('#wf2-graph-target-select')?.value || '';
        const outcome = mount.querySelector('#wf2-graph-outcome-select')?.value || '';
        await callbacks.onAddOutcomeEdge(fromStep, toStep, outcome);
        return;
      }

      if (action === 'delete-edge') {
        const rawId = actionEl.getAttribute('data-edge-id');
        const [fromStep, outcomePart, toStep] = rawId.split('|');
        await callbacks.onDeleteEdge(fromStep, toStep, outcomePart || null);
        state.selectedEdgeId = null;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      setStatus(message);
      callbacks?.onIssue?.({ level: 'error', message });
    }
  });

  async function refresh(yamlText) {
    const seq = ++state.refreshSeq;

    if (!String(yamlText || '').trim()) {
      state.graph = null;
      state.lastError = null;
      callbacks?.onIssues?.([]);
      setStatus('Empty');
      render();
      return;
    }

    try {
      const result = parseDraftWorkflowGraph(yamlText);

      if (seq !== state.refreshSeq) {
        return;
      }

      state.graph = result.graph;
      callbacks?.onIssues?.(result.issues || []);

      const firstError = (result.issues || []).find((item) => item.level === 'error');
      state.lastError = !result.graph?.nodes?.length && firstError ? firstError.message : null;

      if (!state.selectedNodeId && !state.selectedEdgeId) {
        state.selectedNodeId = result.graph?.start || result.graph?.nodes?.[0]?.id || null;
      }

      setStatus(firstError ? 'Issues' : 'Draft');
      render();
    } catch (err) {
      if (seq !== state.refreshSeq) {
        return;
      }

      const message = err instanceof Error ? err.message : String(err);
      state.graph = null;
      state.lastError = message;
      callbacks?.onIssues?.([{ level: 'error', message }]);
      setStatus('Error');
      render();
    }
  }

  renderToolbar();
  render();

  return {
    setCatalog(nextCatalog) {
      state.catalog = nextCatalog;
      renderToolbar();
      render();
    },
    refresh,
    debouncedRefresh: debounce(refresh, 250),
  };
}