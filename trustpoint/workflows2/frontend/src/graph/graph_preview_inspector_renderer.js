import { escapeHtml } from '../core/dom.js';

function renderTargetOptions(graph, selectedNodeId = null) {
  const endTargets = ['$end', '$reject'];
  const realTargets = (graph.nodes || [])
    .filter((node) => !node.is_virtual && node.id !== selectedNodeId)
    .map((node) => `<option value="${escapeHtml(node.id)}">${escapeHtml(node.id)}</option>`)
    .join('');

  const virtualTargets = endTargets
    .map((target) => `<option value="${escapeHtml(target)}">${escapeHtml(target)}</option>`)
    .join('');

  return `${realTargets}${virtualTargets}`;
}

export function renderGraphToolbarOptions(catalog) {
  const steps = catalog?.steps || [];
  return steps
    .map((step) => `<option value="${escapeHtml(step.type)}">${escapeHtml(step.title || step.type)}</option>`)
    .join('');
}

export function renderGraphInspector(graph, catalog, selectedNodeId, selectedEdgeId) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];
  const selectedNode = nodes.find((node) => node.id === selectedNodeId) || null;
  const selectedEdge = edges.find((edge) => edge.id === selectedEdgeId) || null;

  if (selectedNode) {
    if (selectedNode.is_virtual) {
      return `
        <div class="wf2-graph-panel-title">Terminal target</div>
        <div class="text-muted mb-3">
          <code>${escapeHtml(selectedNode.id)}</code>
        </div>
        <div class="small text-muted">
          This is a virtual terminal target derived from the workflow flow.
        </div>
      `;
    }

    const typeOptions = (catalog?.steps || [])
      .map((step) => {
        const selected = step.type === selectedNode.type ? ' selected' : '';
        return `<option value="${escapeHtml(step.type)}"${selected}>${escapeHtml(step.title || step.type)}</option>`;
      })
      .join('');

    const outgoing = edges.filter((edge) => edge.from === selectedNode.id);
    const hasLinearEdge = outgoing.some((edge) => !edge.on);
    const existingOutcomes = new Set(outgoing.filter((edge) => edge.on).map((edge) => edge.on));
    const missingOutcomes = (selectedNode.outcomes || []).filter((outcome) => !existingOutcomes.has(outcome));

    return `
      <div class="wf2-graph-panel-title">Step: ${escapeHtml(selectedNode.id)}</div>

      <div class="mb-3">
        <label class="form-label form-label-sm">Title</label>
        <div class="d-flex gap-2">
          <input
            type="text"
            class="form-control form-control-sm"
            id="wf2-graph-title-input"
            value="${escapeHtml(selectedNode.title || '')}"
          >
          <button class="btn btn-sm btn-outline-primary" data-graph-action="save-title" data-step-id="${escapeHtml(selectedNode.id)}">
            Save
          </button>
        </div>
      </div>

      <div class="mb-3">
        <label class="form-label form-label-sm">Type</label>
        <div class="d-flex gap-2">
          <select class="form-select form-select-sm" id="wf2-graph-type-select">
            ${typeOptions}
          </select>
          <button class="btn btn-sm btn-outline-primary" data-graph-action="apply-type" data-step-id="${escapeHtml(selectedNode.id)}">
            Apply
          </button>
        </div>
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-2">Actions</div>
        <div class="d-flex flex-wrap gap-2">
          <button
            class="btn btn-sm btn-outline-primary"
            data-graph-action="set-start"
            data-step-id="${escapeHtml(selectedNode.id)}"
            ${graph.start === selectedNode.id ? 'disabled' : ''}
          >
            Set as start
          </button>

          <button
            class="btn btn-sm btn-outline-danger"
            data-graph-action="delete-step"
            data-step-id="${escapeHtml(selectedNode.id)}"
          >
            Delete step
          </button>
        </div>
      </div>

      ${
        selectedNode.produces_outcome
          ? `
            <div class="mb-3">
              <div class="fw-semibold mb-2">Add outcome edge</div>
              <div class="d-flex flex-column gap-2">
                <select class="form-select form-select-sm" id="wf2-graph-outcome-select">
                  ${
                    (missingOutcomes.length ? missingOutcomes : selectedNode.outcomes || [])
                      .map((outcome) => `<option value="${escapeHtml(outcome)}">${escapeHtml(outcome)}</option>`)
                      .join('')
                  }
                </select>
                <select class="form-select form-select-sm" id="wf2-graph-target-select">
                  ${renderTargetOptions(graph, selectedNode.id)}
                </select>
                <button
                  class="btn btn-sm btn-outline-primary"
                  data-graph-action="add-outcome-edge"
                  data-step-id="${escapeHtml(selectedNode.id)}"
                >
                  Add outcome edge
                </button>
              </div>
            </div>
          `
          : `
            <div class="mb-3">
              <div class="fw-semibold mb-2">Add linear edge</div>
              ${
                hasLinearEdge
                  ? `<div class="small text-muted">This step already has a linear outgoing edge.</div>`
                  : `
                    <div class="d-flex flex-column gap-2">
                      <select class="form-select form-select-sm" id="wf2-graph-target-select">
                        ${renderTargetOptions(graph, selectedNode.id)}
                      </select>
                      <button
                        class="btn btn-sm btn-outline-primary"
                        data-graph-action="add-linear-edge"
                        data-step-id="${escapeHtml(selectedNode.id)}"
                      >
                        Add linear edge
                      </button>
                    </div>
                  `
              }
            </div>
          `
      }

      <div>
        <div class="fw-semibold mb-2">Outcomes</div>
        <div class="small text-muted">
          ${
            Array.isArray(selectedNode.outcomes) && selectedNode.outcomes.length
              ? escapeHtml(selectedNode.outcomes.join(', '))
              : 'None'
          }
        </div>
      </div>
    `;
  }

  if (selectedEdge) {
    return `
      <div class="wf2-graph-panel-title">Edge</div>

      <div class="mb-3">
        <div><strong>from:</strong> <code>${escapeHtml(selectedEdge.from)}</code></div>
        <div><strong>to:</strong> <code>${escapeHtml(selectedEdge.to)}</code></div>
        <div><strong>on:</strong> <code>${escapeHtml(selectedEdge.on || '(linear)')}</code></div>
      </div>

      <button
        class="btn btn-sm btn-outline-danger"
        data-graph-action="delete-edge"
        data-edge-id="${escapeHtml(selectedEdge.id)}"
      >
        Delete edge
      </button>
    `;
  }

  return `
    <div class="wf2-graph-panel-title">Flow editor</div>
    <div class="text-muted mb-3">
      Select a node or edge to edit it.
    </div>
    <div class="small text-muted">
      Nodes: ${nodes.filter((node) => !node.is_virtual).length}<br>
      Edges: ${edges.length}
    </div>
  `;
}

export function renderGraphNotice(message) {
  if (!message) {
    return '';
  }

  const canRepairStart = /workflow\.start/.test(message);

  return `
    <div class="alert alert-warning py-2 px-3 mb-3">
      <div class="fw-semibold mb-1">Graph issue</div>
      <div class="small mb-2">${escapeHtml(message)}</div>
      ${
        canRepairStart
          ? `
            <button type="button" class="btn btn-sm btn-outline-warning" data-graph-action="repair-start">
              Repair workflow.start
            </button>
          `
          : ''
      }
    </div>
  `;
}