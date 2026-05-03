export function edgeId(edge) {
  return `${edge.from}|${edge.on || ''}|${edge.to}`;
}

function buildVirtualNode(id) {
  return {
    id,
    type: 'virtual',
    title: id,
    produces_outcome: false,
    outcomes: [],
    is_terminal: false,
    is_virtual: true,
  };
}

export function normalizeGraph(graph) {
  const realNodes = Array.isArray(graph?.nodes)
    ? graph.nodes.filter((node) => node?.id)
    : [];
  const realNodeIds = new Set(realNodes.map((node) => node.id));
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];

  const virtualNodes = [];
  const seenVirtual = new Set();

  function ensureVirtual(id) {
    if (!id || realNodeIds.has(id) || seenVirtual.has(id)) {
      return;
    }

    seenVirtual.add(id);
    virtualNodes.push(buildVirtualNode(id));
  }

  for (const edge of edges) {
    ensureVirtual(edge.from);
    ensureVirtual(edge.to);
  }

  return {
    ...graph,
    nodes: [
      ...realNodes.map((node) => ({
        ...node,
        is_virtual: false,
      })),
      ...virtualNodes,
    ],
    edges: edges.map((edge) => ({
      ...edge,
      id: edgeId(edge),
    })),
  };
}
