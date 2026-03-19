function debounce(fn, wait) {
  let timer = null;
  return (...args) => {
    clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), wait);
  };
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

async function postJson(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
    },
    credentials: 'same-origin',
    body: JSON.stringify(payload),
  });

  let data;
  try {
    data = await res.json();
  } catch {
    throw new Error(`Invalid JSON response from ${url}`);
  }

  if (!res.ok) {
    throw new Error(data?.error || `HTTP ${res.status}`);
  }

  return data;
}

function edgeId(edge) {
  return `${edge.from}|${edge.on || ''}|${edge.to}`;
}

function truncate(value, max = 28) {
  const s = String(value || '');
  if (s.length <= max) return s;
  return `${s.slice(0, max - 1)}…`;
}

function normalizeGraph(graph) {
  const realNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const realNodeIds = new Set(realNodes.map((node) => node.id));
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];

  const virtualTargets = [];
  for (const edge of edges) {
    if (!realNodeIds.has(edge.to) && !virtualTargets.find((item) => item.id === edge.to)) {
      virtualTargets.push({
        id: edge.to,
        type: 'terminal',
        title: edge.to,
        produces_outcome: false,
        outcomes: [],
        is_terminal: true,
        is_virtual: true,
      });
    }
  }

  return {
    ...graph,
    nodes: [
      ...realNodes.map((node) => ({
        ...node,
        is_virtual: false,
      })),
      ...virtualTargets,
    ],
    edges: edges.map((edge) => ({
      ...edge,
      id: edgeId(edge),
    })),
  };
}

function buildLayout(graph) {
  const nodes = Array.isArray(graph.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph.edges) ? graph.edges : [];

  const nodeIds = new Set(nodes.map((node) => node.id));
  const adjacency = new Map();
  for (const node of nodes) {
    adjacency.set(node.id, []);
  }

  for (const edge of edges) {
    if (nodeIds.has(edge.from) && nodeIds.has(edge.to)) {
      adjacency.get(edge.from).push(edge.to);
    }
  }

  const levels = new Map();
  const startId = graph.start && nodeIds.has(graph.start) ? graph.start : nodes[0]?.id || null;

  if (startId) {
    const queue = [startId];
    levels.set(startId, 0);

    while (queue.length) {
      const current = queue.shift();
      const currentLevel = levels.get(current) || 0;

      for (const next of adjacency.get(current) || []) {
        if (!levels.has(next)) {
          levels.set(next, currentLevel + 1);
          queue.push(next);
        }
      }
    }
  }

  let maxAssignedLevel = levels.size ? Math.max(...levels.values()) : 0;
  for (const node of nodes) {
    if (!levels.has(node.id)) {
      maxAssignedLevel += 1;
      levels.set(node.id, maxAssignedLevel);
    }
  }

  const groups = new Map();
  for (const node of nodes) {
    const level = levels.get(node.id) || 0;
    if (!groups.has(level)) {
      groups.set(level, []);
    }
    groups.get(level).push(node);
  }

  const sortedLevels = Array.from(groups.keys()).sort((a, b) => a - b);
  const positions = new Map();

  const nodeWidth = 190;
  const nodeHeight = 76;
  const xGap = 250;
  const yGap = 130;
  const xStart = 40;
  const yStart = 40;

  for (const level of sortedLevels) {
    const group = groups.get(level) || [];
    group.forEach((node, index) => {
      positions.set(node.id, {
        x: xStart + level * xGap,
        y: yStart + index * yGap,
        w: nodeWidth,
        h: nodeHeight,
      });
    });
  }

  const maxX = Math.max(...Array.from(positions.values()).map((p) => p.x + p.w), 420);
  const maxY = Math.max(...Array.from(positions.values()).map((p) => p.y + p.h), 240);

  return {
    positions,
    width: maxX + 40,
    height: maxY + 40,
  };
}

function renderSvg(graph, layout, selectedNodeId, selectedEdgeId) {
  const defs = `
    <defs>
      <marker id="wf2-arrow" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#6c757d"></path>
      </marker>
      <marker id="wf2-arrow-selected" markerWidth="10" markerHeight="10" refX="8" refY="3" orient="auto">
        <path d="M0,0 L0,6 L8,3 z" fill="#0d6efd"></path>
      </marker>
    </defs>
  `;

  const edgeSvg = (graph.edges || [])
    .map((edge) => {
      const from = layout.positions.get(edge.from);
      const to = layout.positions.get(edge.to);
      if (!from || !to) {
        return '';
      }

      const x1 = from.x + from.w;
      const y1 = from.y + from.h / 2;
      const x2 = to.x;
      const y2 = to.y + to.h / 2;
      const dx = Math.max(60, Math.abs(x2 - x1) / 2);

      const path = `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
      const selected = edge.id === selectedEdgeId;
      const labelX = (x1 + x2) / 2;
      const labelY = (y1 + y2) / 2 - 8;

      return `
        <g class="wf2-graph-edge ${selected ? 'is-selected' : ''}" data-edge-id="${escapeHtml(edge.id)}">
          <path
            d="${path}"
            fill="none"
            stroke="${selected ? '#0d6efd' : '#6c757d'}"
            stroke-width="${selected ? '3' : '2'}"
            marker-end="url(#${selected ? 'wf2-arrow-selected' : 'wf2-arrow'})"
          ></path>
          ${
            edge.on
              ? `<text x="${labelX}" y="${labelY}" class="wf2-graph-edge-label">${escapeHtml(edge.on)}</text>`
              : ''
          }
        </g>
      `;
    })
    .join('');

  const nodeSvg = (graph.nodes || [])
    .map((node) => {
      const pos = layout.positions.get(node.id);
      if (!pos) {
        return '';
      }

      const selected = node.id === selectedNodeId;
      const fill = node.is_virtual ? '#fff8e1' : '#ffffff';
      const stroke = selected ? '#0d6efd' : '#adb5bd';
      const dash = node.is_virtual ? '6 4' : 'none';

      return `
        <g class="wf2-graph-node ${selected ? 'is-selected' : ''}" data-node-id="${escapeHtml(node.id)}">
          <rect
            x="${pos.x}"
            y="${pos.y}"
            width="${pos.w}"
            height="${pos.h}"
            rx="12"
            ry="12"
            fill="${fill}"
            stroke="${stroke}"
            stroke-width="${selected ? '3' : '1.5'}"
            stroke-dasharray="${dash}"
          ></rect>

          <text x="${pos.x + 14}" y="${pos.y + 24}" class="wf2-graph-node-title">
            ${escapeHtml(truncate(node.title || node.id, 28))}
          </text>

          <text x="${pos.x + 14}" y="${pos.y + 45}" class="wf2-graph-node-meta">
            ${escapeHtml(node.id)}
          </text>

          <text x="${pos.x + 14}" y="${pos.y + 62}" class="wf2-graph-node-meta">
            ${escapeHtml(node.type || '')}
          </text>

          ${
            graph.start === node.id
              ? `<text x="${pos.x + pos.w - 44}" y="${pos.y + 20}" class="wf2-graph-badge">START</text>`
              : ''
          }
        </g>
      `;
    })
    .join('');

  return `
    <svg
      class="wf2-graph-svg"
      viewBox="0 0 ${layout.width} ${layout.height}"
      width="${layout.width}"
      height="${layout.height}"
      preserveAspectRatio="xMinYMin meet"
      xmlns="http://www.w3.org/2000/svg"
    >
      ${defs}
      ${edgeSvg}
      ${nodeSvg}
    </svg>
  `;
}

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

function renderInspector(graph, catalog, selectedNodeId, selectedEdgeId) {
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

function renderNotice(message) {
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

export function createInteractiveGraph({
  mount,
  graphUrl,
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

  function reportIssue(message, level = 'error') {
    callbacks?.onIssue?.({ level, message });
  }

  function renderToolbar() {
    const steps = state.catalog?.steps || [];
    refs.addStepSelect.innerHTML = steps
      .map((step) => `<option value="${escapeHtml(step.type)}">${escapeHtml(step.title || step.type)}</option>`)
      .join('');
  }

  function render() {
    refs.notice.innerHTML = renderNotice(state.lastError);

    if (!state.graph) {
      refs.canvas.innerHTML = '<div class="wf2-graph-canvas-empty">No valid graph available yet.</div>';
      refs.inspector.innerHTML = renderInspector(null, state.catalog, null, null);
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

    const layout = buildLayout(graph);
    refs.canvas.innerHTML = renderSvg(graph, layout, state.selectedNodeId, state.selectedEdgeId);
    refs.inspector.innerHTML = renderInspector(graph, state.catalog, state.selectedNodeId, state.selectedEdgeId);
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
      if (action === 'repair-start') {
        await callbacks.onRepairStart();
        state.lastError = null;
        return;
      }

      if (action === 'add-step') {
        const stepType = refs.addStepSelect.value;
        if (!stepType) return;
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
      reportIssue(message, 'error');
    }
  });

  async function refresh(yamlText) {
    if (!String(yamlText || '').trim()) {
      state.graph = null;
      state.lastError = null;
      setStatus('Empty');
      render();
      return;
    }

    const seq = ++state.refreshSeq;
    setStatus('Updating…');

    try {
      const graph = await postJson(graphUrl, {
        yaml_text: yamlText,
      });

      if (seq !== state.refreshSeq) {
        return;
      }

      state.graph = graph;
      state.lastError = null;

      if (!state.selectedNodeId && !state.selectedEdgeId) {
        state.selectedNodeId = graph.start || graph.nodes?.[0]?.id || null;
      }

      setStatus('Live');
      render();
    } catch (err) {
      if (seq !== state.refreshSeq) {
        return;
      }

      const message = err instanceof Error ? err.message : String(err);
      state.lastError = message;
      setStatus('Issue');
      reportIssue(message, 'error');
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
    debouncedRefresh: debounce(refresh, 450),
  };
}