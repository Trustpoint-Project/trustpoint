export function buildGraphLayout(graph, manualPositions = {}) {
  const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const edges = Array.isArray(graph?.edges) ? graph.edges : [];

  const positions = new Map();

  const nodeWidth = 190;
  const nodeHeight = 76;
  const xGap = 250;
  const yGap = 130;
  const xStart = 40;
  const yStart = 40;

  const manualIds = new Set(
    Object.keys(manualPositions || {}).filter((id) => manualPositions[id]),
  );

  const autoNodes = nodes.filter((node) => !manualIds.has(node.id));
  const nodeIds = new Set(autoNodes.map((node) => node.id));

  const adjacency = new Map();
  for (const node of autoNodes) {
    adjacency.set(node.id, []);
  }

  for (const edge of edges) {
    if (nodeIds.has(edge.from) && nodeIds.has(edge.to)) {
      adjacency.get(edge.from).push(edge.to);
    }
  }

  const levels = new Map();
  const startId =
    graph?.start && nodeIds.has(graph.start)
      ? graph.start
      : autoNodes[0]?.id || null;

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
  for (const node of autoNodes) {
    if (!levels.has(node.id)) {
      maxAssignedLevel += 1;
      levels.set(node.id, maxAssignedLevel);
    }
  }

  const groups = new Map();
  for (const node of autoNodes) {
    const level = levels.get(node.id) || 0;
    if (!groups.has(level)) {
      groups.set(level, []);
    }
    groups.get(level).push(node);
  }

  const sortedLevels = Array.from(groups.keys()).sort((a, b) => a - b);
  for (const level of sortedLevels) {
    const group = (groups.get(level) || []).slice().sort((left, right) => {
      const virtualDelta = Number(Boolean(left?.is_virtual)) - Number(Boolean(right?.is_virtual));
      if (virtualDelta !== 0) {
        return virtualDelta;
      }
      return String(left?.id || '').localeCompare(String(right?.id || ''));
    });
    group.forEach((node, index) => {
      positions.set(node.id, {
        x: xStart + level * xGap,
        y: yStart + index * yGap,
        w: nodeWidth,
        h: nodeHeight,
      });
    });
  }

  for (const node of nodes) {
    const manual = manualPositions?.[node.id];
    if (manual && Number.isFinite(manual.x) && Number.isFinite(manual.y)) {
      positions.set(node.id, {
        x: manual.x,
        y: manual.y,
        w: nodeWidth,
        h: nodeHeight,
      });
    }
  }

  const allRects = Array.from(positions.values());
  const maxX = Math.max(...allRects.map((p) => p.x + p.w), 420);
  const maxY = Math.max(...allRects.map((p) => p.y + p.h), 240);

  return {
    positions,
    width: maxX + 80,
    height: maxY + 80,
    nodeWidth,
    nodeHeight,
  };
}
