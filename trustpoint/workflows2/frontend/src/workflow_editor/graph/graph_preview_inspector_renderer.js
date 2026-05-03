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

function summarizeStepBehavior(node) {
  const step = node?.step_data || {};

  if (node?.type === 'webhook') {
    const method = typeof step.method === 'string' ? step.method : '';
    const url = typeof step.url === 'string' ? step.url : '';
    const captureCount = step.capture && typeof step.capture === 'object' ? Object.keys(step.capture).length : 0;
    return `${method || 'HTTP'} ${url || 'request'}${captureCount ? ` · captures ${captureCount} value${captureCount === 1 ? '' : 's'}` : ''}`;
  }

  if (node?.type === 'email') {
    const recipients = Array.isArray(step.to) ? step.to.length : 0;
    return `Sends an email${recipients ? ` to ${recipients} recipient${recipients === 1 ? '' : 's'}` : ''}`;
  }

  if (node?.type === 'logic') {
    const cases = Array.isArray(step.cases) ? step.cases.length : 0;
    return `Evaluates ${cases} case${cases === 1 ? '' : 's'}${step.default ? ` · default ${step.default}` : ''}`;
  }

  if (node?.type === 'set') {
    const vars = step.vars && typeof step.vars === 'object' ? Object.keys(step.vars).length : 0;
    return `Writes ${vars} workflow var${vars === 1 ? '' : 's'}`;
  }

  if (node?.type === 'compute') {
    const vars = step.set && typeof step.set === 'object' ? Object.keys(step.set).length : 0;
    return `Computes ${vars} workflow var${vars === 1 ? '' : 's'}`;
  }

  if (node?.type === 'approval') {
    return `Waits for approval · approved => ${step.approved_outcome || '-'} · rejected => ${step.rejected_outcome || '-'}`;
  }

  return node?.title || node?.type || 'No summary available';
}

function renderEdgeList(edges) {
  if (!edges.length) {
    return '<div class="small text-muted">None</div>';
  }

  return `
    <ul class="small mb-0 ps-3">
      ${edges
        .map((edge) => `<li><code>${escapeHtml(edge.from)}</code>${edge.on ? ` on <code>${escapeHtml(edge.on)}</code>` : ''} → <code>${escapeHtml(edge.to)}</code></li>`)
        .join('')}
    </ul>
  `;
}

function renderNodeSummary(node, graph) {
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  const incoming = edges.filter((edge) => edge.to === node.id);
  const outgoing = edges.filter((edge) => edge.from === node.id);

  return `
    <div class="wf2-graph-panel-title">Selected step</div>

    <div class="mb-3">
      <div><strong>ID:</strong> <code>${escapeHtml(node.id)}</code></div>
      <div><strong>Type:</strong> <code>${escapeHtml(node.type || '-')}</code></div>
      <div><strong>Title:</strong> ${escapeHtml(node.title || '-')}</div>
      <div><strong>Start:</strong> ${graph?.start === node.id ? 'Yes' : 'No'}</div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">What happens here</div>
      <div class="small text-muted">${escapeHtml(summarizeStepBehavior(node))}</div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Comes from</div>
      ${renderEdgeList(incoming)}
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Goes to</div>
      ${renderEdgeList(outgoing)}
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
