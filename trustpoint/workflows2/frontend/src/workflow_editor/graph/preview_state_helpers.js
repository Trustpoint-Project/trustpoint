export function clearEditor(state) {
  state.editorNodeId = null;
  state.editorEdgeId = null;
}

export function clearCanvasMenu(state) {
  state.canvasMenuPos = null;
}

export function clearSelection(state) {
  state.selectedNodeId = null;
  state.selectedEdgeId = null;
}

export function openNodeEditor(state, nodeId) {
  state.selectedNodeId = nodeId;
  state.selectedEdgeId = null;
  state.editorNodeId = nodeId;
  state.editorEdgeId = null;
  clearCanvasMenu(state);
}

export function openEdgeEditor(state, edgeId) {
  state.selectedEdgeId = edgeId;
  state.selectedNodeId = null;
  state.editorEdgeId = edgeId;
  state.editorNodeId = null;
  clearCanvasMenu(state);
}

export function openCanvasMenu(state, position) {
  clearSelection(state);
  clearEditor(state);
  state.canvasMenuPos = position;
}
