export function attachGraphCanvasInteractions({
  canvasEl,
  getLayout,
  onSelectNode,
  onSelectEdge,
  onOpenNodeEditor,
  onOpenEdgeEditor,
  onOpenCanvasMenu,
  onClearSelection,
  onSetDragNode,
  onMoveNode,
  onSetConnectionPreview,
  onCompleteConnection,
  render,
}) {
  const state = {
    dragNodeId: null,
    dragOffsetX: 0,
    dragOffsetY: 0,
    connectFromNodeId: null,
    connectOrigin: null,
    didDrag: false,
  };

  function getSvgPoint(event) {
    const svg = canvasEl.querySelector('svg');
    if (!svg || !svg.getScreenCTM()) {
      return null;
    }

    const point = svg.createSVGPoint();
    point.x = event.clientX;
    point.y = event.clientY;

    return point.matrixTransform(svg.getScreenCTM().inverse());
  }

  function resetConnection() {
    state.connectFromNodeId = null;
    state.connectOrigin = null;
    onSetConnectionPreview(null);
  }

  function handleClick(event) {
    if (state.didDrag) {
      state.didDrag = false;
      return;
    }

    if (event.target.closest('.wf2-graph-floating-card')) {
      return;
    }

    const nodeEl = event.target.closest('[data-node-id]');
    if (nodeEl) {
      onSelectNode(nodeEl.getAttribute('data-node-id'));
      return;
    }

    const edgeEl = event.target.closest('[data-edge-id]');
    if (edgeEl) {
      onSelectEdge(edgeEl.getAttribute('data-edge-id'));
      return;
    }

    onClearSelection();
  }

  function handleDoubleClick(event) {
    if (event.target.closest('.wf2-graph-floating-card')) {
      return;
    }

    const nodeEl = event.target.closest('[data-node-id]');
    if (nodeEl) {
      event.preventDefault();
      onOpenNodeEditor(nodeEl.getAttribute('data-node-id'));
      return;
    }

    const edgeEl = event.target.closest('[data-edge-id]');
    if (edgeEl) {
      event.preventDefault();
      onOpenEdgeEditor(edgeEl.getAttribute('data-edge-id'));
    }
  }

  function handleContextMenu(event) {
    if (event.target.closest('.wf2-graph-floating-card')) {
      return;
    }

    const point = getSvgPoint(event);
    if (!point) {
      return;
    }

    event.preventDefault();

    const nodeEl = event.target.closest('[data-node-id]');
    if (nodeEl) {
      onOpenNodeEditor(nodeEl.getAttribute('data-node-id'));
      return;
    }

    const edgeEl = event.target.closest('[data-edge-id]');
    if (edgeEl) {
      onOpenEdgeEditor(edgeEl.getAttribute('data-edge-id'));
      return;
    }

    onOpenCanvasMenu(point);
  }

  function handleMouseDown(event) {
    if (event.button !== 0) {
      return;
    }

    if (event.target.closest('.wf2-graph-floating-card')) {
      return;
    }

    const point = getSvgPoint(event);
    if (!point) {
      return;
    }

    const handleEl = event.target.closest('[data-node-handle]');
    if (handleEl) {
      const nodeId = handleEl.getAttribute('data-node-handle');
      const layout = getLayout();
      const pos = layout?.positions?.get(nodeId);
      if (!pos) {
        return;
      }

      state.connectFromNodeId = nodeId;
      state.connectOrigin = {
        fromX: pos.x + pos.w,
        fromY: pos.y + pos.h / 2,
      };

      onSetConnectionPreview({
        fromX: state.connectOrigin.fromX,
        fromY: state.connectOrigin.fromY,
        toX: state.connectOrigin.fromX + 20,
        toY: state.connectOrigin.fromY,
      });

      render();
      event.preventDefault();
      return;
    }

    const nodeEl = event.target.closest('[data-node-id]');
    if (!nodeEl) {
      return;
    }

    const nodeId = nodeEl.getAttribute('data-node-id');
    const layout = getLayout();
    const pos = layout?.positions?.get(nodeId);
    if (!pos) {
      return;
    }

    state.dragNodeId = nodeId;
    state.dragOffsetX = point.x - pos.x;
    state.dragOffsetY = point.y - pos.y;
    state.didDrag = false;

    onSelectNode(nodeId);
    onSetDragNode(nodeId);
    event.preventDefault();
  }

  function handleMouseMove(event) {
    const point = getSvgPoint(event);
    if (!point) {
      return;
    }

    if (state.dragNodeId) {
      state.didDrag = true;
      onMoveNode(state.dragNodeId, {
        x: point.x - state.dragOffsetX,
        y: point.y - state.dragOffsetY,
      });
      render();
      return;
    }

    if (state.connectFromNodeId && state.connectOrigin) {
      onSetConnectionPreview({
        fromX: state.connectOrigin.fromX,
        fromY: state.connectOrigin.fromY,
        toX: point.x,
        toY: point.y,
      });
      render();
    }
  }

  async function handleMouseUp(event) {
    if (state.dragNodeId) {
      state.dragNodeId = null;
      onSetDragNode(null);
      render();
      return;
    }

    if (state.connectFromNodeId) {
      const sourceId = state.connectFromNodeId;
      const targetEl = event.target?.closest?.('[data-node-id]');
      resetConnection();
      render();

      if (targetEl) {
        const targetId = targetEl.getAttribute('data-node-id');
        if (targetId && targetId !== sourceId) {
          await onCompleteConnection(sourceId, targetId);
        }
      }
    }
  }

  canvasEl.addEventListener('click', handleClick);
  canvasEl.addEventListener('dblclick', handleDoubleClick);
  canvasEl.addEventListener('contextmenu', handleContextMenu);
  canvasEl.addEventListener('mousedown', handleMouseDown);
  window.addEventListener('mousemove', handleMouseMove);
  window.addEventListener('mouseup', handleMouseUp);

  return {
    destroy() {
      canvasEl.removeEventListener('click', handleClick);
      canvasEl.removeEventListener('dblclick', handleDoubleClick);
      canvasEl.removeEventListener('contextmenu', handleContextMenu);
      canvasEl.removeEventListener('mousedown', handleMouseDown);
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    },
  };
}