import { parseDocument } from 'yaml';

import { debounce } from './graph_preview_http.js';
import { buildGraphLayout } from './graph_preview_layout.js';
import { normalizeGraph } from './graph_preview_model.js';
import { renderGraphNotice, renderGraphToolbarOptions } from './graph_preview_inspector_renderer.js';
import { renderGraphSvg } from './graph_preview_svg_renderer.js';
import { parseDraftWorkflowGraph } from './draft_workflow_graph_parser.js';
import { attachGraphCanvasInteractions } from './graph_canvas_interactions.js';
import { renderGraphFloatingEditor } from './graph_floating_editor_renderer.js';
import { reconcileGraphNodePositions } from './graph_position_session.js';
import { renderCanvasContextMenu } from './graph_canvas_context_menu_renderer.js';

function parseEdgeId(rawId) {
  const [fromStep, outcomePart, toStep] = String(rawId || '').split('|');
  return {
    fromStep,
    outcome: outcomePart || null,
    toStep,
  };
}

function parseConditionPath(rawPath) {
  try {
    const parsed = JSON.parse(String(rawPath || '[]'));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function findNode(graph, nodeId) {
  return (graph?.nodes || []).find((node) => node.id === nodeId) || null;
}

function freezeMissingNodePositions(graph, currentPositions) {
  const next = { ...currentPositions };
  const seedLayout = buildGraphLayout(graph, currentPositions);

  for (const node of graph?.nodes || []) {
    if (next[node.id]) {
      continue;
    }

    const pos = seedLayout?.positions?.get(node.id);
    if (!pos) {
      continue;
    }

    next[node.id] = {
      x: pos.x,
      y: pos.y,
    };
  }

  return next;
}

function snapshotStepDataById(yamlText) {
  try {
    const doc = parseDocument(yamlText, { prettyErrors: true });
    if (doc.errors.length) {
      return {};
    }

    const rootObj = doc.toJS() || {};
    const steps = rootObj?.workflow?.steps;

    if (!steps || typeof steps !== 'object' || Array.isArray(steps)) {
      return {};
    }

    return steps;
  } catch {
    return {};
  }
}

function readInputValue(scope, selector) {
  return scope?.querySelector(selector)?.value ?? '';
}

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

    editorNodeId: null,
    editorEdgeId: null,

    canvasMenuPos: null,

    refreshSeq: 0,
    lastError: null,
    normalizedGraph: null,
    layout: null,
    nodePositions: {},
    stepDataById: {},
    dragNodeId: null,
    connectPreview: null,
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
          <div id="wf2-graph-canvas" class="wf2-graph-canvas"></div>
        </div>
      </div>
    </div>
  `;

  const refs = {
    addStepSelect: mount.querySelector('#wf2-graph-add-step-select'),
    canvas: mount.querySelector('#wf2-graph-canvas'),
    notice: mount.querySelector('#wf2-graph-notice'),
  };

  function setStatus(value) {
    if (statusEl) {
      statusEl.textContent = value;
    }
  }

  function clearEditor() {
    state.editorNodeId = null;
    state.editorEdgeId = null;
  }

  function clearCanvasMenu() {
    state.canvasMenuPos = null;
  }

  function clearSelection() {
    state.selectedNodeId = null;
    state.selectedEdgeId = null;
  }

  function renderToolbar() {
    refs.addStepSelect.innerHTML = renderGraphToolbarOptions(state.catalog);
  }

  function renderEmptyState(message) {
    refs.canvas.innerHTML = `<div class="wf2-graph-canvas-empty-state">${message}</div>`;
  }

  function render() {
    refs.notice.innerHTML = renderGraphNotice(state.lastError);

    if (!state.graph) {
      renderEmptyState('No graph available yet.');
      state.normalizedGraph = null;
      state.layout = null;
      return;
    }

    const graph = normalizeGraph(state.graph);

    state.nodePositions = freezeMissingNodePositions(graph, state.nodePositions);
    const layout = buildGraphLayout(graph, state.nodePositions);

    state.normalizedGraph = graph;
    state.layout = layout;

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

    const svgHtml = renderGraphSvg(
      graph,
      layout,
      state.selectedNodeId,
      state.selectedEdgeId,
      state.connectPreview,
      state.dragNodeId,
    );

    refs.canvas.innerHTML = `
      <div class="wf2-graph-canvas-stage">
        ${svgHtml}
        <div class="wf2-graph-overlay-root"></div>
      </div>
    `;

    const overlayRoot = refs.canvas.querySelector('.wf2-graph-overlay-root');

    renderGraphFloatingEditor({
      rootEl: overlayRoot,
      graph,
      layout,
      catalog: state.catalog,
      openNodeId: state.editorNodeId,
      openEdgeId: state.editorEdgeId,
      stepDataById: state.stepDataById,
    });

    if (state.canvasMenuPos) {
      overlayRoot.insertAdjacentHTML(
        'beforeend',
        renderCanvasContextMenu({
          catalog: state.catalog,
          position: state.canvasMenuPos,
          canvasWidth: layout.width,
          canvasHeight: layout.height,
        }),
      );
    }
  }

  async function createConnection(fromNodeId, toNodeId) {
    const graph = state.normalizedGraph;
    const fromNode = findNode(graph, fromNodeId);

    if (!fromNode || fromNode.is_virtual) {
      return;
    }

    if (fromNode.produces_outcome) {
      const allOutcomes = fromNode.outcomes || [];
      if (!allOutcomes.length) {
        callbacks?.onIssue?.({
          level: 'warning',
          message: `Step "${fromNodeId}" has no known outcomes.`,
        });
        return;
      }

      const existing = new Set(
        (graph.edges || [])
          .filter((edge) => edge.from === fromNodeId && edge.on)
          .map((edge) => edge.on),
      );

      const preferred = allOutcomes.filter((outcome) => !existing.has(outcome));
      const selectedOutcome = preferred[0] || allOutcomes[0];

      await callbacks.onAddOutcomeEdge(fromNodeId, toNodeId, selectedOutcome);
      return;
    }

    await callbacks.onAddLinearEdge(fromNodeId, toNodeId);
  }

  async function deleteCurrentSelection() {
    if (state.selectedEdgeId) {
      const { fromStep, outcome, toStep } = parseEdgeId(state.selectedEdgeId);
      await callbacks.onDeleteEdge(fromStep, toStep, outcome);
      state.selectedEdgeId = null;
      state.editorEdgeId = null;
      return true;
    }

    if (state.selectedNodeId) {
      const confirmed = window.confirm(
        `Delete step "${state.selectedNodeId}"?\n\nOutgoing edges will be removed. Incoming linear edges will be removed. Incoming outcome edges will be rerouted to $end.`,
      );
      if (!confirmed) {
        return false;
      }

      await callbacks.onDeleteStep(state.selectedNodeId);
      state.selectedNodeId = null;
      state.editorNodeId = null;
      return true;
    }

    return false;
  }

  const interactions = attachGraphCanvasInteractions({
    canvasEl: refs.canvas,
    getLayout: () => state.layout,

    onSelectNode(nodeId) {
      state.selectedNodeId = nodeId;
      state.selectedEdgeId = null;
      clearCanvasMenu();
      render();
    },

    onSelectEdge(edgeId) {
      state.selectedEdgeId = edgeId;
      state.selectedNodeId = null;
      clearCanvasMenu();
      render();
    },

    onOpenNodeEditor(nodeId) {
      state.selectedNodeId = nodeId;
      state.selectedEdgeId = null;
      state.editorNodeId = nodeId;
      state.editorEdgeId = null;
      clearCanvasMenu();
      render();
    },

    onOpenEdgeEditor(edgeId) {
      state.selectedEdgeId = edgeId;
      state.selectedNodeId = null;
      state.editorEdgeId = edgeId;
      state.editorNodeId = null;
      clearCanvasMenu();
      render();
    },

    onOpenCanvasMenu(position) {
      clearSelection();
      clearEditor();
      state.canvasMenuPos = position;
      render();
    },

    onClearSelection() {
      clearSelection();
      clearEditor();
      clearCanvasMenu();
      render();
    },

    onSetDragNode(nodeId) {
      state.dragNodeId = nodeId;
    },

    onMoveNode(nodeId, pos) {
      state.nodePositions[nodeId] = pos;
    },

    onSetConnectionPreview(preview) {
      state.connectPreview = preview;
    },

    async onCompleteConnection(fromNodeId, toNodeId) {
      await createConnection(fromNodeId, toNodeId);
    },

    render,
  });

  mount.addEventListener('click', async (event) => {
    const actionEl = event.target.closest('[data-graph-action], [data-graph-overlay-action]');
    if (!actionEl) {
      return;
    }

    const action =
      actionEl.getAttribute('data-graph-overlay-action') ||
      actionEl.getAttribute('data-graph-action');

    const scope = actionEl.closest('.wf2-graph-floating-card') || mount;
    const path = parseConditionPath(actionEl.getAttribute('data-condition-path'));

    try {
      if (action === 'close-editor') {
        clearEditor();
        clearCanvasMenu();
        render();
        return;
      }

      if (action === 'close-canvas-menu') {
        clearCanvasMenu();
        render();
        return;
      }

      if (action === 'add-step') {
        const stepType = refs.addStepSelect.value;
        if (!stepType) {
          return;
        }

        const result = await callbacks.onAddStep(stepType);
        if (result?.stepId) {
          state.selectedNodeId = result.stepId;
          state.selectedEdgeId = null;
          state.editorNodeId = result.stepId;
          state.editorEdgeId = null;
          clearCanvasMenu();
        }
        return;
      }

      if (action === 'context-add-step') {
        const stepType = actionEl.getAttribute('data-step-type');
        if (!stepType) {
          return;
        }

        const menuPos = state.canvasMenuPos;
        const result = await callbacks.onAddStep(stepType);

        if (result?.stepId && menuPos) {
          state.nodePositions[result.stepId] = {
            x: Math.max(40, menuPos.x - 95),
            y: Math.max(40, menuPos.y - 38),
          };
          state.selectedNodeId = result.stepId;
          state.selectedEdgeId = null;
          state.editorNodeId = result.stepId;
          state.editorEdgeId = null;
        }

        clearCanvasMenu();
        return;
      }

      if (action === 'save-node-title' || action === 'save-title') {
        const stepId = actionEl.getAttribute('data-step-id');
        const titleInput = scope.querySelector('[data-node-title-input="true"]');
        const title = titleInput?.value || '';
        await callbacks.onSetTitle(stepId, title);
        return;
      }

      if (action === 'save-step-field') {
        const stepId = actionEl.getAttribute('data-step-id');
        const fieldKey = actionEl.getAttribute('data-field-key');
        const row = actionEl.closest('[data-step-field-row]');
        const rawValue = readInputValue(row, '[data-step-field-input="true"]');
        await callbacks.onSaveStepField(stepId, fieldKey, rawValue);
        return;
      }

      if (action === 'add-optional-field') {
        const stepId = actionEl.getAttribute('data-step-id');
        const fieldKey = actionEl.getAttribute('data-field-key');
        await callbacks.onAddOptionalField(stepId, fieldKey);
        return;
      }

      if (action === 'remove-step-field') {
        const stepId = actionEl.getAttribute('data-step-id');
        const fieldKey = actionEl.getAttribute('data-field-key');
        await callbacks.onRemoveStepField(stepId, fieldKey);
        return;
      }

      if (action === 'add-logic-case') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onAddLogicCase(stepId);
        return;
      }

      if (action === 'remove-logic-case') {
        const stepId = actionEl.getAttribute('data-step-id');
        const index = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        await callbacks.onRemoveLogicCase(stepId, index);
        return;
      }

      if (action === 'save-logic-case-outcome') {
        const stepId = actionEl.getAttribute('data-step-id');
        const index = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        const row = actionEl.closest('[data-logic-case-row]');
        const outcome = readInputValue(row, '[data-logic-case-outcome-input="true"]');
        await callbacks.onSaveLogicCaseOutcome(stepId, index, outcome);
        return;
      }

      if (action === 'save-logic-default') {
        const stepId = actionEl.getAttribute('data-step-id');
        const outcome = readInputValue(scope, '[data-logic-default-input="true"]');
        await callbacks.onSaveLogicDefault(stepId, outcome);
        return;
      }

      if (action === 'set-logic-condition-kind') {
        const stepId = actionEl.getAttribute('data-step-id');
        const caseIndex = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        const nodeScope = actionEl.closest('[data-condition-node-path]');
        const kind = readInputValue(nodeScope, '[data-condition-kind-select="true"]');
        await callbacks.onSetLogicConditionKind(stepId, caseIndex, path, kind);
        return;
      }

      if (action === 'save-logic-compare-node') {
        const stepId = actionEl.getAttribute('data-step-id');
        const caseIndex = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        const nodeScope = actionEl.closest('[data-condition-node-path]');

        await callbacks.onSaveLogicCompareNode(
          stepId,
          caseIndex,
          path,
          readInputValue(nodeScope, '[data-logic-compare-left="true"]'),
          readInputValue(nodeScope, '[data-logic-compare-op="true"]'),
          readInputValue(nodeScope, '[data-logic-compare-right="true"]'),
        );
        return;
      }

      if (action === 'save-logic-exists-node') {
        const stepId = actionEl.getAttribute('data-step-id');
        const caseIndex = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        const nodeScope = actionEl.closest('[data-condition-node-path]');

        await callbacks.onSaveLogicExistsNode(
          stepId,
          caseIndex,
          path,
          readInputValue(nodeScope, '[data-logic-exists-value="true"]'),
        );
        return;
      }

      if (action === 'add-logic-condition-child') {
        const stepId = actionEl.getAttribute('data-step-id');
        const caseIndex = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        await callbacks.onAddLogicConditionChild(stepId, caseIndex, path);
        return;
      }

      if (action === 'remove-logic-condition-node') {
        const stepId = actionEl.getAttribute('data-step-id');
        const caseIndex = Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10);
        await callbacks.onRemoveLogicConditionNode(stepId, caseIndex, path);
        return;
      }

      if (action === 'add-webhook-capture-rule') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onAddWebhookCaptureRule(stepId);
        return;
      }

      if (action === 'save-webhook-capture-rule') {
        const stepId = actionEl.getAttribute('data-step-id');
        const oldTarget = actionEl.getAttribute('data-capture-target');
        const row = actionEl.closest('[data-capture-row]');

        await callbacks.onSaveWebhookCaptureRule(
          stepId,
          oldTarget,
          readInputValue(row, '[data-capture-target-input="true"]'),
          readInputValue(row, '[data-capture-source-input="true"]'),
        );
        return;
      }

      if (action === 'remove-webhook-capture-rule') {
        const stepId = actionEl.getAttribute('data-step-id');
        const target = actionEl.getAttribute('data-capture-target');
        await callbacks.onRemoveWebhookCaptureRule(stepId, target);
        return;
      }

      if (action === 'add-compute-assignment') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onAddComputeAssignment(stepId);
        return;
      }

      if (action === 'save-compute-assignment') {
        const stepId = actionEl.getAttribute('data-step-id');
        const oldTarget = actionEl.getAttribute('data-compute-target');
        const row = actionEl.closest('[data-compute-row]');

        await callbacks.onSaveComputeAssignment(
          stepId,
          oldTarget,
          readInputValue(row, '[data-compute-target-input="true"]'),
          readInputValue(row, '[data-compute-operator-input="true"]'),
          readInputValue(row, '[data-compute-args-input="true"]'),
        );
        return;
      }

      if (action === 'remove-compute-assignment') {
        const stepId = actionEl.getAttribute('data-step-id');
        const target = actionEl.getAttribute('data-compute-target');
        await callbacks.onRemoveComputeAssignment(stepId, target);
        return;
      }

      if (action === 'add-set-var-entry') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onAddSetVarEntry(stepId);
        return;
      }

      if (action === 'save-set-var-entry') {
        const stepId = actionEl.getAttribute('data-step-id');
        const oldKey = actionEl.getAttribute('data-set-var-key');
        const row = actionEl.closest('[data-set-var-row]');

        await callbacks.onSaveSetVarEntry(
          stepId,
          oldKey,
          readInputValue(row, '[data-set-var-key-input="true"]'),
          readInputValue(row, '[data-set-var-value-input="true"]'),
        );
        return;
      }

      if (action === 'remove-set-var-entry') {
        const stepId = actionEl.getAttribute('data-step-id');
        const key = actionEl.getAttribute('data-set-var-key');
        await callbacks.onRemoveSetVarEntry(stepId, key);
        return;
      }

      if (action === 'set-start') {
        const stepId = actionEl.getAttribute('data-step-id');
        await callbacks.onSetStart(stepId);
        return;
      }

      if (action === 'delete-step') {
        const stepId = actionEl.getAttribute('data-step-id');
        const confirmed = window.confirm(
          `Delete step "${stepId}"?\n\nOutgoing edges will be removed. Incoming linear edges will be removed. Incoming outcome edges will be rerouted to $end.`,
        );
        if (!confirmed) {
          return;
        }

        await callbacks.onDeleteStep(stepId);
        state.selectedNodeId = null;
        state.selectedEdgeId = null;
        state.editorNodeId = null;
        state.editorEdgeId = null;
        return;
      }

      if (action === 'rename-edge-outcome') {
        const rawId = actionEl.getAttribute('data-edge-id');
        const { fromStep, outcome, toStep } = parseEdgeId(rawId);
        const newOutcome = readInputValue(scope, '[data-edge-outcome-input="true"]');
        await callbacks.onUpdateEdgeOutcome(fromStep, toStep, outcome, newOutcome);
        return;
      }

      if (action === 'delete-edge') {
        const rawId = actionEl.getAttribute('data-edge-id');
        const { fromStep, outcome, toStep } = parseEdgeId(rawId);
        await callbacks.onDeleteEdge(fromStep, toStep, outcome);
        state.selectedEdgeId = null;
        state.editorEdgeId = null;
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
      state.nodePositions = {};
      state.stepDataById = {};
      clearSelection();
      clearEditor();
      clearCanvasMenu();
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

      setStatus(firstError ? 'Issues' : 'Draft');
      render();
    } catch (err) {
      if (seq !== state.refreshSeq) {
        return;
      }

      const message = err instanceof Error ? err.message : String(err);
      state.graph = null;
      state.stepDataById = {};
      state.lastError = message;
      clearSelection();
      clearEditor();
      clearCanvasMenu();
      callbacks?.onIssues?.([{ level: 'error', message, offset: err?.offset ?? null }]);
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
    async deleteSelection() {
      return deleteCurrentSelection();
    },
    hasSelection() {
      return Boolean(state.selectedNodeId || state.selectedEdgeId);
    },
    closeEditor() {
      clearEditor();
      clearCanvasMenu();
      render();
    },
    destroy() {
      interactions.destroy();
    },
  };
}