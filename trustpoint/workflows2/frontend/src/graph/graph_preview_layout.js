export function buildGraphLayout(graph) {
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