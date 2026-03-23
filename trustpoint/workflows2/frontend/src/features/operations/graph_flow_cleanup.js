function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== '';
}

function normalizeOutcome(edge) {
  return isNonEmptyString(edge?.on) ? edge.on.trim() : null;
}

function normalizeFlowEdge(edge) {
  if (!edge || typeof edge !== 'object') {
    return null;
  }

  const from = isNonEmptyString(edge.from) ? edge.from.trim() : null;
  const to = isNonEmptyString(edge.to) ? edge.to.trim() : null;
  const on = normalizeOutcome(edge);

  if (!from || !to) {
    return null;
  }

  return on ? { from, on, to } : { from, to };
}

export function normalizeFlow(flow) {
  const out = [];
  const seenLinear = new Set();
  const seenOutcome = new Set();

  for (const rawEdge of flow || []) {
    const edge = normalizeFlowEdge(rawEdge);
    if (!edge) {
      continue;
    }

    if (isNonEmptyString(edge.on)) {
      const key = `${edge.from}|${edge.on}`;
      if (seenOutcome.has(key)) {
        continue;
      }
      seenOutcome.add(key);
      out.push(edge);
      continue;
    }

    if (seenLinear.has(edge.from)) {
      continue;
    }

    seenLinear.add(edge.from);
    out.push(edge);
  }

  return out;
}

export function cleanupFlowForDeletedStep(flow, deletedStepId) {
  const nextFlow = [];
  const reroutedOutcomeEdges = [];
  const removedIncomingLinearEdges = [];
  const removedOutgoingEdges = [];

  for (const rawEdge of flow || []) {
    const edge = normalizeFlowEdge(rawEdge);
    if (!edge) {
      continue;
    }

    if (edge.from === deletedStepId) {
      removedOutgoingEdges.push(edge);
      continue;
    }

    if (edge.to === deletedStepId) {
      if (isNonEmptyString(edge.on)) {
        const rerouted = {
          from: edge.from,
          on: edge.on,
          to: '$end',
        };
        nextFlow.push(rerouted);
        reroutedOutcomeEdges.push(rerouted);
      } else {
        removedIncomingLinearEdges.push(edge);
      }
      continue;
    }

    nextFlow.push(edge);
  }

  return {
    flow: normalizeFlow(nextFlow),
    reroutedOutcomeEdges,
    removedIncomingLinearEdges,
    removedOutgoingEdges,
  };
}

export function pickReplacementStartStep(steps, deletedStepId, currentStart) {
  const remainingStepIds = Object.keys(steps).filter((stepId) => stepId !== deletedStepId);

  if (!remainingStepIds.length) {
    return '';
  }

  if (currentStart && currentStart !== deletedStepId && remainingStepIds.includes(currentStart)) {
    return currentStart;
  }

  return remainingStepIds[0];
}