import { escapeHtml } from '../shared/dom.js';

export function renderGraphToolbarOptions(catalog) {
  const steps = catalog?.steps || [];
  if (!steps.length) {
    return '<option value="">No step types</option>';
  }

  return steps
    .map(
      (step) =>
        `<option value="${escapeHtml(step.type)}">${escapeHtml(step.title || step.type)}</option>`,
    )
    .join('');
}

export function renderGraphNotice(message) {
  if (!message) {
    return '';
  }

  return `
    <div class="alert alert-warning py-2 px-3 mb-0">
      <div class="fw-semibold mb-1">Graph issue</div>
      <div class="small">${escapeHtml(message)}</div>
    </div>
  `;
}

function renderNodeSummary(node, graph) {
  return `
    <div class="wf2-graph-panel-title">Selected step</div>

    <div class="mb-3">
      <div><strong>ID:</strong> <code>${escapeHtml(node.id)}</code></div>
      <div><strong>Type:</strong> <code>${escapeHtml(node.type || '-')}</code></div>
      <div><strong>Title:</strong> ${escapeHtml(node.title || '-')}</div>
      <div><strong>Start:</strong> ${graph?.start === node.id ? 'Yes' : 'No'}</div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Outcomes</div>
      <div class="small text-muted">
        ${
          Array.isArray(node.outcomes) && node.outcomes.length
            ? escapeHtml(node.outcomes.join(', '))
            : 'None'
        }
      </div>
    </div>

    <div class="small text-muted">
      Drag the node to reposition it. Drag from the blue handle to another node to connect it.
      Click the floating card on the canvas to edit the step directly.
    </div>
  `;
}

function renderEdgeSummary(edge) {
  return `
    <div class="wf2-graph-panel-title">Selected edge</div>

    <div class="mb-3">
      <div><strong>From:</strong> <code>${escapeHtml(edge.from)}</code></div>
      <div><strong>To:</strong> <code>${escapeHtml(edge.to)}</code></div>
      <div><strong>Outcome:</strong> <code>${escapeHtml(edge.on || '(linear)')}</code></div>
    </div>

    <div class="small text-muted">
      Use the floating card on the canvas to edit or delete this edge.
    </div>
  `;
}

export function renderGraphInspector(graph, catalog, selectedNodeId, selectedEdgeId) {
  if (!graph) {
    return `
      <div class="wf2-graph-panel-title">Flow editor</div>
      <div class="text-muted">
        No graph available yet.
      </div>
    `;
  }

  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];

  const selectedNode = nodes.find((node) => node.id === selectedNodeId) || null;
  const selectedEdge = edges.find((edge) => edge.id === selectedEdgeId) || null;

  if (selectedNode) {
    return renderNodeSummary(selectedNode, graph);
  }

  if (selectedEdge) {
    return renderEdgeSummary(selectedEdge);
  }

  return `
    <div class="wf2-graph-panel-title">Flow editor</div>

    <div class="mb-3 text-muted">
      Select a node or edge to inspect it.
    </div>

    <div class="mb-3">
      <div><strong>Nodes:</strong> ${nodes.length}</div>
      <div><strong>Edges:</strong> ${edges.length}</div>
      <div><strong>Start:</strong> <code>${escapeHtml(graph.start || '-')}</code></div>
    </div>

    <div class="small text-muted">
      Use the toolbar to add steps. Drag nodes to reposition them. Drag from the blue handle to another node to create a connection.
    </div>
  `;
}
