import { escapeHtml } from '../core/dom.js';

function truncate(value, max = 28) {
  const s = String(value || '');
  if (s.length <= max) {
    return s;
  }
  return `${s.slice(0, max - 1)}…`;
}

function edgePath(from, to) {
  const x1 = from.x + from.w;
  const y1 = from.y + from.h / 2;
  const x2 = to.x;
  const y2 = to.y + to.h / 2;
  const dx = Math.max(60, Math.abs(x2 - x1) / 2);

  return {
    path: `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`,
    labelX: (x1 + x2) / 2,
    labelY: (y1 + y2) / 2 - 8,
  };
}

function renderConnectionPreview(connectPreview) {
  if (!connectPreview) {
    return '';
  }

  return `
    <path
      class="wf2-graph-connection-preview"
      d="M ${connectPreview.fromX} ${connectPreview.fromY} C ${connectPreview.fromX + 60} ${connectPreview.fromY}, ${connectPreview.toX - 60} ${connectPreview.toY}, ${connectPreview.toX} ${connectPreview.toY}"
    ></path>
  `;
}

export function renderGraphSvg(
  graph,
  layout,
  selectedNodeId,
  selectedEdgeId,
  connectPreview = null,
  dragNodeId = null,
) {
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

  const background = `
    <rect
      data-graph-background="true"
      x="0"
      y="0"
      width="${layout.width}"
      height="${layout.height}"
      fill="transparent"
    ></rect>
  `;

  const edgeSvg = (graph.edges || [])
    .map((edge) => {
      const from = layout.positions.get(edge.from);
      const to = layout.positions.get(edge.to);
      if (!from || !to) {
        return '';
      }

      const { path, labelX, labelY } = edgePath(from, to);
      const selected = edge.id === selectedEdgeId;

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
              ? `
                <text
                  x="${labelX}"
                  y="${labelY}"
                  class="wf2-graph-edge-label"
                  data-edge-label-id="${escapeHtml(edge.id)}"
                >
                  ${escapeHtml(edge.on)}
                </text>
              `
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
      const dragging = node.id === dragNodeId;
      const fill = node.is_virtual ? '#fff8e1' : '#ffffff';
      const stroke = selected ? '#0d6efd' : '#adb5bd';
      const dash = node.is_virtual ? '6 4' : 'none';

      return `
        <g
          class="wf2-graph-node ${selected ? 'is-selected' : ''} ${dragging ? 'is-dragging' : ''}"
          data-node-id="${escapeHtml(node.id)}"
        >
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

          ${
            !node.is_virtual
              ? `
                <circle
                  class="wf2-graph-output-handle"
                  data-node-handle="${escapeHtml(node.id)}"
                  cx="${pos.x + pos.w}"
                  cy="${pos.y + pos.h / 2}"
                  r="7"
                ></circle>
              `
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
      ${background}
      ${renderConnectionPreview(connectPreview)}
      ${edgeSvg}
      ${nodeSvg}
    </svg>
  `;
}