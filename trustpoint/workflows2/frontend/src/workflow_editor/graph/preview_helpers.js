import { parseDocument } from 'yaml';
import { decodeConditionPath } from '../document/condition_tree.js';
import { buildGraphLayout } from './graph_preview_layout.js';

export function parseEdgeId(rawId) {
  const [fromStep, outcomePart, toStep] = String(rawId || '').split('|');
  return {
    fromStep,
    outcome: outcomePart || null,
    toStep,
  };
}

export function parseConditionPath(rawPath) {
  return decodeConditionPath(rawPath);
}

export function findNode(graph, nodeId) {
  return (graph?.nodes || []).find((node) => node.id === nodeId) || null;
}

export function freezeMissingNodePositions(graph, currentPositions) {
  const nextPositions = { ...currentPositions };
  const seedLayout = buildGraphLayout(graph, currentPositions);

  for (const node of graph?.nodes || []) {
    if (nextPositions[node.id]) {
      continue;
    }

    const position = seedLayout?.positions?.get(node.id);
    if (!position) {
      continue;
    }

    nextPositions[node.id] = {
      x: position.x,
      y: position.y,
    };
  }

  return nextPositions;
}

export function snapshotStepDataById(yamlText) {
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

export function readInputValue(scope, selector) {
  return scope?.querySelector(selector)?.value ?? '';
}

export function getOverlayStateKey(state) {
  if (state?.editorNodeId) {
    return `node:${state.editorNodeId}`;
  }

  if (state?.editorEdgeId) {
    return `edge:${state.editorEdgeId}`;
  }

  if (state?.canvasMenuPos) {
    return 'menu';
  }

  return null;
}

export function readOverlayScroll(rootEl) {
  const body = rootEl?.querySelector('.wf2-graph-floating-body');
  if (!body) {
    return null;
  }

  return {
    top: body.scrollTop || 0,
    left: body.scrollLeft || 0,
  };
}

export function restoreOverlayScroll(rootEl, scrollState) {
  const body = rootEl?.querySelector('.wf2-graph-floating-body');
  if (!body || !scrollState) {
    return;
  }

  body.scrollTop = scrollState.top || 0;
  body.scrollLeft = scrollState.left || 0;
}

export function createGraphPreviewState(catalog) {
  return {
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
    overlayScrollKey: null,
    overlayScroll: null,
  };
}
