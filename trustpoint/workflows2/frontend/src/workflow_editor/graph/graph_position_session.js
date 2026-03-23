export function reconcileGraphNodePositions(graph, existingPositions, buildGraphLayout) {
  const safeExisting = existingPositions && typeof existingPositions === 'object'
    ? existingPositions
    : {};

  const autoLayout = buildGraphLayout(graph, {});
  const nextPositions = {};

  for (const node of graph?.nodes || []) {
    const existing = safeExisting[node.id];
    if (
      existing &&
      Number.isFinite(existing.x) &&
      Number.isFinite(existing.y)
    ) {
      nextPositions[node.id] = {
        x: existing.x,
        y: existing.y,
      };
      continue;
    }

    const auto = autoLayout.positions.get(node.id);
    if (auto) {
      nextPositions[node.id] = {
        x: auto.x,
        y: auto.y,
      };
    }
  }

  return nextPositions;
}