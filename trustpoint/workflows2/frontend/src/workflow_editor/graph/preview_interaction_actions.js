import { findNode, parseEdgeId } from './preview_helpers.js';
import {
  clearCanvasMenu,
  clearEditor,
  clearSelection,
  openCanvasMenu,
  openEdgeEditor,
  openNodeEditor,
} from './preview_state_helpers.js';

export async function createConnection(state, callbacks, fromNodeId, toNodeId) {
  const fromNode = findNode(state.normalizedGraph, fromNodeId);
  const toNode = findNode(state.normalizedGraph, toNodeId);
  if (!fromNode || !toNode) {
    callbacks?.onIssue?.({
      level: 'warning',
      message: 'Cannot create connection because one of the selected nodes is no longer available.',
    });
    return;
  }

  if (fromNode.is_trigger || fromNode.is_apply) {
    if (toNode.is_virtual) {
      callbacks?.onIssue?.({
        level: 'warning',
        message: 'Event and apply nodes can only connect to real workflow steps.',
      });
      return;
    }

    await callbacks.onSetStart(toNodeId);
    return;
  }

  if (fromNode.is_virtual) {
    callbacks?.onIssue?.({
      level: 'warning',
      message: 'Virtual targets cannot start new connections.',
    });
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
      (state.normalizedGraph?.edges || [])
        .filter((edge) => edge.from === fromNodeId && edge.on)
        .map((edge) => edge.on),
    );

    const selectedOutcome = allOutcomes.find((outcome) => !existing.has(outcome)) || allOutcomes[0];
    await callbacks.onAddOutcomeEdge(fromNodeId, toNodeId, selectedOutcome);
    return;
  }

  await callbacks.onAddLinearEdge(fromNodeId, toNodeId);
}

export async function deleteCurrentSelection(state, callbacks) {
  if (state.selectedEdgeId) {
    const selectedEdge = (state.normalizedGraph?.edges || []).find((edge) => edge.id === state.selectedEdgeId);
    if (selectedEdge?.is_helper_edge || selectedEdge?.is_start_edge) {
      callbacks?.onIssue?.({
        level: 'warning',
        message: 'The event/apply/start helper path is derived from YAML and cannot be deleted directly.',
      });
      return false;
    }

    const { fromStep, outcome, toStep } = parseEdgeId(state.selectedEdgeId);
    await callbacks.onDeleteEdge(fromStep, toStep, outcome);
    state.selectedEdgeId = null;
    state.editorEdgeId = null;
    return true;
  }

  if (state.selectedNodeId) {
    const selectedNode = findNode(state.normalizedGraph, state.selectedNodeId);
    if (selectedNode?.is_virtual) {
      callbacks?.onIssue?.({
        level: 'warning',
        message: 'Virtual graph nodes are derived from YAML and cannot be deleted.',
      });
      return false;
    }

    const confirmed = window.confirm(
      `Delete step "${state.selectedNodeId}"?\n\nOutgoing edges will be removed. Incoming edges that targeted this step will be removed as well.`,
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

export function createInteractionCallbacks(state, render, callbacks) {
  return {
    onSelectNode(nodeId) {
      state.selectedNodeId = nodeId;
      state.selectedEdgeId = null;
      clearCanvasMenu(state);
      render();
    },

    onSelectEdge(edgeId) {
      state.selectedEdgeId = edgeId;
      state.selectedNodeId = null;
      clearCanvasMenu(state);
      render();
    },

    onOpenNodeEditor(nodeId) {
      openNodeEditor(state, nodeId);
      render();
    },

    onOpenEdgeEditor(edgeId) {
      openEdgeEditor(state, edgeId);
      render();
    },

    onOpenCanvasMenu(position) {
      openCanvasMenu(state, position);
      render();
    },

    onClearSelection() {
      clearSelection(state);
      clearEditor(state);
      clearCanvasMenu(state);
      render();
    },

    onSetDragNode(nodeId) {
      state.dragNodeId = nodeId;
    },

    onMoveNode(nodeId, position) {
      state.nodePositions[nodeId] = position;
    },

    onSetConnectionPreview(preview) {
      state.connectPreview = preview;
    },

    async onCompleteConnection(fromNodeId, toNodeId) {
      await createConnection(state, callbacks, fromNodeId, toNodeId);
    },

    render,
  };
}
