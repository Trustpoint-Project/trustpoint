import { renderGraphEdgeEditorOverlay } from './graph_edge_editor_renderer.js';
import { renderGraphStepEditorOverlay } from './graph_step_field_editor_renderer.js';

export function renderGraphFloatingEditor({
  rootEl,
  graph,
  layout,
  catalog,
  openNodeId,
  openEdgeId,
  stepDataById = {},
}) {
  if (!rootEl) {
    return;
  }

  if (!graph || !layout) {
    rootEl.innerHTML = '';
    return;
  }

  const openNode = (graph.nodes || []).find((node) => node.id === openNodeId) || null;
  const openEdge = (graph.edges || []).find((edge) => edge.id === openEdgeId) || null;

  if (openNode) {
    rootEl.innerHTML = renderGraphStepEditorOverlay({
      graph,
      layout,
      catalog,
      node: openNode,
      stepData: stepDataById?.[openNode.id] || {},
    });
    return;
  }

  if (openEdge) {
    rootEl.innerHTML = renderGraphEdgeEditorOverlay({
      layout,
      edge: openEdge,
    });
    return;
  }

  rootEl.innerHTML = '';
}