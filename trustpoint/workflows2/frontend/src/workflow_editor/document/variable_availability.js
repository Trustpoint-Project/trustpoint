import { uniqStrings } from './value_utils.js';

const END_TARGETS = new Set(['$end', '$reject']);

function normalizeWorkflowVarName(rawName) {
  if (typeof rawName !== 'string') {
    return null;
  }

  const trimmed = rawName.trim();
  if (!trimmed) {
    return null;
  }

  if (trimmed.startsWith('vars.')) {
    const stripped = trimmed.slice(5).trim();
    return stripped || null;
  }

  return trimmed;
}

function sortedUnique(values) {
  return uniqStrings(values).sort((a, b) => a.localeCompare(b));
}

function normalizeFlowEdges(rootObj, stepsObj) {
  const flowList = Array.isArray(rootObj?.workflow?.flow) ? rootObj.workflow.flow : [];

  return flowList
    .map((item) => {
      if (!item || typeof item !== 'object' || Array.isArray(item)) {
        return null;
      }

      const from = typeof item.from === 'string' ? item.from.trim() : '';
      const to = typeof item.to === 'string' ? item.to.trim() : '';
      if (!from || !to) {
        return null;
      }

      if (!Object.prototype.hasOwnProperty.call(stepsObj, from)) {
        return null;
      }

      if (!Object.prototype.hasOwnProperty.call(stepsObj, to) && !END_TARGETS.has(to)) {
        return null;
      }

      return { from, to };
    })
    .filter(Boolean);
}

function collectReachableStepIds(startStepId, stepsObj, edges) {
  if (!startStepId || !Object.prototype.hasOwnProperty.call(stepsObj, startStepId)) {
    return new Set();
  }

  const outgoing = new Map();
  for (const edge of edges) {
    if (!Object.prototype.hasOwnProperty.call(stepsObj, edge.to)) {
      continue;
    }

    if (!outgoing.has(edge.from)) {
      outgoing.set(edge.from, []);
    }
    outgoing.get(edge.from).push(edge.to);
  }

  const reachable = new Set();
  const pending = [startStepId];

  while (pending.length) {
    const stepId = pending.pop();
    if (!stepId || reachable.has(stepId) || !Object.prototype.hasOwnProperty.call(stepsObj, stepId)) {
      continue;
    }

    reachable.add(stepId);
    for (const nextStepId of outgoing.get(stepId) || []) {
      if (!reachable.has(nextStepId)) {
        pending.push(nextStepId);
      }
    }
  }

  return reachable;
}

function buildPredecessorMap(stepIds, edges, reachable) {
  const predecessors = new Map(stepIds.map((stepId) => [stepId, new Set()]));

  for (const edge of edges) {
    if (!reachable.has(edge.from) || !reachable.has(edge.to)) {
      continue;
    }

    predecessors.get(edge.to)?.add(edge.from);
  }

  return predecessors;
}

function copySet(source) {
  return new Set(source || []);
}

function intersectSets(sets) {
  if (!Array.isArray(sets) || !sets.length) {
    return new Set();
  }

  const result = copySet(sets[0]);
  for (let index = 1; index < sets.length; index += 1) {
    const nextSet = sets[index] || new Set();
    for (const value of Array.from(result)) {
      if (!nextSet.has(value)) {
        result.delete(value);
      }
    }
  }

  return result;
}

function setsEqual(left, right) {
  if (left.size !== right.size) {
    return false;
  }

  for (const value of left) {
    if (!right.has(value)) {
      return false;
    }
  }

  return true;
}

export function extractStepProducedVarNames(stepObj) {
  if (!stepObj || typeof stepObj !== 'object' || Array.isArray(stepObj)) {
    return [];
  }

  const produced = [];

  if (stepObj.type === 'set' && stepObj.vars && typeof stepObj.vars === 'object' && !Array.isArray(stepObj.vars)) {
    for (const key of Object.keys(stepObj.vars)) {
      const name = normalizeWorkflowVarName(key);
      if (name) {
        produced.push(name);
      }
    }
  }

  if (stepObj.type === 'compute' && stepObj.set && typeof stepObj.set === 'object' && !Array.isArray(stepObj.set)) {
    for (const key of Object.keys(stepObj.set)) {
      const name = normalizeWorkflowVarName(key);
      if (name) {
        produced.push(name);
      }
    }
  }

  if (stepObj.type === 'webhook' && stepObj.capture && typeof stepObj.capture === 'object' && !Array.isArray(stepObj.capture)) {
    for (const key of Object.keys(stepObj.capture)) {
      const name = normalizeWorkflowVarName(key);
      if (name) {
        produced.push(name);
      }
    }
  }

  return sortedUnique(produced);
}

export function analyzeWorkflowVariableAvailability(rootObj) {
  const stepsObj =
    rootObj?.workflow?.steps && typeof rootObj.workflow.steps === 'object' && !Array.isArray(rootObj.workflow.steps)
      ? rootObj.workflow.steps
      : {};

  const stepIds = Object.keys(stepsObj);
  const producedByStepId = {};
  const allProduced = [];

  for (const stepId of stepIds) {
    const producedVarNames = extractStepProducedVarNames(stepsObj[stepId]);
    producedByStepId[stepId] = producedVarNames;
    allProduced.push(...producedVarNames);
  }

  const rawStart = typeof rootObj?.workflow?.start === 'string' ? rootObj.workflow.start.trim() : '';
  const startStepId = rawStart && Object.prototype.hasOwnProperty.call(stepsObj, rawStart) ? rawStart : null;
  const edges = normalizeFlowEdges(rootObj, stepsObj);
  const reachable = collectReachableStepIds(startStepId, stepsObj, edges);
  const predecessors = buildPredecessorMap(stepIds, edges, reachable);
  const reachableProducedUniverse = new Set(
    Array.from(reachable).flatMap((stepId) => producedByStepId[stepId] || []),
  );

  const availableBefore = {};
  const availableAfter = {};

  for (const stepId of stepIds) {
    if (!reachable.has(stepId) || stepId === startStepId) {
      availableBefore[stepId] = new Set();
    } else {
      availableBefore[stepId] = copySet(reachableProducedUniverse);
    }

    availableAfter[stepId] = new Set([
      ...availableBefore[stepId],
      ...(producedByStepId[stepId] || []),
    ]);
  }

  let changed = true;
  while (changed) {
    changed = false;

    for (const stepId of stepIds) {
      if (!reachable.has(stepId)) {
        continue;
      }

      const nextBefore =
        stepId === startStepId
          ? new Set()
          : intersectSets(
              Array.from(predecessors.get(stepId) || []).map(
                (predecessorId) => availableAfter[predecessorId] || new Set(),
              ),
            );

      if (!setsEqual(nextBefore, availableBefore[stepId])) {
        availableBefore[stepId] = nextBefore;
        changed = true;
      }

      const nextAfter = new Set([
        ...nextBefore,
        ...(producedByStepId[stepId] || []),
      ]);

      if (!setsEqual(nextAfter, availableAfter[stepId])) {
        availableAfter[stepId] = nextAfter;
        changed = true;
      }
    }
  }

  const stepAvailability = {};
  for (const stepId of stepIds) {
    stepAvailability[stepId] = {
      isReachable: reachable.has(stepId),
      availableVarNames: sortedUnique(Array.from(availableBefore[stepId] || [])),
      availableAfterVarNames: sortedUnique(Array.from(availableAfter[stepId] || [])),
      producedVarNames: producedByStepId[stepId] || [],
    };
  }

  return {
    startStepId,
    reachableStepIds: Array.from(reachable),
    allWorkflowVarNames: sortedUnique(allProduced),
    stepAvailability,
  };
}
