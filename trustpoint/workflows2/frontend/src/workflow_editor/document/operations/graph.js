import {
  extractStepOutcomes,
  findStepSpec,
  isOutcomeProducingStep,
  makeUniqueStepId,
} from '../catalog_metadata.js';
import {
  cleanupFlowForDeletedStep,
  END_TARGETS,
  normalizeFlow,
  pickReplacementStartStep,
} from '../flow_document.js';
import {
  deepClone,
  getFlow,
  getSteps,
  getWorkflow,
  parseRoot,
  stringifyRoot,
} from '../yaml_document.js';

function validateExistingStep(steps, stepId, label = 'Step') {
  if (!stepId || !Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`${label} "${stepId}" not found.`);
  }
}

function validateTarget(steps, toStep) {
  if (!toStep) {
    throw new Error('Target step is required.');
  }

  if (END_TARGETS.has(toStep)) {
    return;
  }

  if (!Object.prototype.hasOwnProperty.call(steps, toStep)) {
    throw new Error(`Target "${toStep}" not found.`);
  }
}

export function repairWorkflowStart({ yamlText }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const stepIds = Object.keys(steps);

  if (!stepIds.length) {
    throw new Error('Cannot repair workflow.start because there are no steps.');
  }

  const currentStart = typeof workflow.start === 'string' ? workflow.start : '';
  if (currentStart && Object.prototype.hasOwnProperty.call(steps, currentStart)) {
    return {
      yamlText,
      changed: false,
      stepId: currentStart,
    };
  }

  workflow.start = stepIds[0];

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
    stepId: stepIds[0],
  };
}

export function addStepToWorkflow({ yamlText, catalog, stepType }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  getFlow(workflow);

  const stepSpec = findStepSpec(catalog, stepType);
  if (!stepSpec) {
    throw new Error(`Unknown step type "${stepType}".`);
  }

  const stepId = makeUniqueStepId(Object.keys(steps), stepType);
  steps[stepId] = deepClone(stepSpec.scaffold || { type: stepType });

  const currentStart = typeof workflow.start === 'string' ? workflow.start : '';
  const startLooksInvalid =
    !currentStart ||
    currentStart.startsWith('__') ||
    !Object.prototype.hasOwnProperty.call(steps, currentStart);

  if (startLooksInvalid) {
    workflow.start = stepId;
  }

  return {
    yamlText: stringifyRoot(rootObj),
    stepId,
  };
}

export function setStepTitle({ yamlText, stepId, title }) {
  const rootObj = parseRoot(yamlText);
  const steps = getSteps(getWorkflow(rootObj));

  validateExistingStep(steps, stepId);

  const stepObj = steps[stepId];
  const trimmed = String(title || '').trim();
  if (trimmed) {
    stepObj.title = trimmed;
  } else {
    delete stepObj.title;
  }

  return {
    yamlText: stringifyRoot(rootObj),
  };
}

export function deleteStepFromWorkflow({ yamlText, stepId }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, stepId);

  if (Object.keys(steps).length <= 1) {
    throw new Error('Cannot delete the last step.');
  }

  const cleaned = cleanupFlowForDeletedStep(flow, stepId);
  delete steps[stepId];
  workflow.flow = cleaned.flow;
  workflow.start = pickReplacementStartStep(steps, stepId, workflow.start);

  return {
    yamlText: stringifyRoot(rootObj),
    deletedOutgoingEdgeCount: cleaned.deletedOutgoingEdgeCount,
    removedIncomingLinearEdgeCount: cleaned.removedIncomingLinearEdgeCount,
    reroutedIncomingOutcomeEdgeCount: cleaned.reroutedIncomingOutcomeEdgeCount,
  };
}

export function addLinearFlowEdge({ yamlText, fromStep, toStep }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, fromStep, 'Source step');
  validateTarget(steps, toStep);

  if (isOutcomeProducingStep(steps[fromStep])) {
    throw new Error(`Step "${fromStep}" produces outcomes and requires outcome-based transitions.`);
  }

  const hasOutcomeRoutes = flow.some(
    (edge) => edge && typeof edge === 'object' && edge.from === fromStep && edge.on,
  );
  if (hasOutcomeRoutes) {
    throw new Error(`Step "${fromStep}" already has outcome-based transitions and cannot also have a linear edge.`);
  }

  let updated = false;
  const nextFlow = flow.map((edge) => {
    if (edge && typeof edge === 'object' && edge.from === fromStep && !edge.on) {
      updated = true;
      return { from: fromStep, to: toStep };
    }
    return edge;
  });

  if (!updated) {
    nextFlow.push({ from: fromStep, to: toStep });
  }

  workflow.flow = normalizeFlow(nextFlow);

  return {
    yamlText: stringifyRoot(rootObj),
  };
}

export function addOutcomeFlowEdge({ yamlText, fromStep, toStep, outcome }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, fromStep, 'Source step');
  validateTarget(steps, toStep);

  const validOutcomes = extractStepOutcomes(steps[fromStep]);
  if (!validOutcomes.length) {
    throw new Error(`Step "${fromStep}" does not produce outcomes and cannot have outcome-based transitions.`);
  }

  const safeOutcome = String(outcome || '').trim();
  if (!safeOutcome || !validOutcomes.includes(safeOutcome)) {
    throw new Error(`Invalid outcome "${outcome}" for step "${fromStep}".`);
  }

  const hasLinearRoute = flow.some(
    (edge) => edge && typeof edge === 'object' && edge.from === fromStep && !edge.on,
  );
  if (hasLinearRoute) {
    throw new Error(`Step "${fromStep}" already has a linear transition and cannot also have outcome-based transitions.`);
  }

  let updated = false;
  const nextFlow = flow.map((edge) => {
    if (edge && typeof edge === 'object' && edge.from === fromStep && edge.on === safeOutcome) {
      updated = true;
      return { from: fromStep, on: safeOutcome, to: toStep };
    }
    return edge;
  });

  if (!updated) {
    nextFlow.push({ from: fromStep, on: safeOutcome, to: toStep });
  }

  workflow.flow = normalizeFlow(nextFlow);

  return {
    yamlText: stringifyRoot(rootObj),
  };
}

export function updateOutcomeFlowEdge({
  yamlText,
  fromStep,
  toStep,
  oldOutcome,
  newOutcome,
}) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, fromStep, 'Source step');

  const validOutcomes = extractStepOutcomes(steps[fromStep]);
  if (!validOutcomes.length) {
    throw new Error(`Step "${fromStep}" has no outcome routes.`);
  }

  const safeOldOutcome = String(oldOutcome || '').trim();
  const safeNewOutcome = String(newOutcome || '').trim();
  if (!safeOldOutcome) {
    throw new Error('Old outcome is required.');
  }
  if (!safeNewOutcome) {
    throw new Error('New outcome is required.');
  }
  if (!validOutcomes.includes(safeNewOutcome)) {
    throw new Error(`Outcome "${safeNewOutcome}" is not valid for "${fromStep}".`);
  }

  const duplicateExists = flow.some(
    (edge) =>
      edge &&
      typeof edge === 'object' &&
      edge.from === fromStep &&
      edge.to === toStep &&
      edge.on === safeNewOutcome &&
      edge.on !== safeOldOutcome,
  );

  if (duplicateExists) {
    throw new Error(`An edge for outcome "${safeNewOutcome}" already exists on "${fromStep}".`);
  }

  let changed = false;
  workflow.flow = normalizeFlow(
    flow.map((edge) => {
      if (
        edge &&
        typeof edge === 'object' &&
        edge.from === fromStep &&
        edge.to === toStep &&
        edge.on === safeOldOutcome
      ) {
        changed = true;
        return { from: fromStep, on: safeNewOutcome, to: toStep };
      }

      return edge;
    }),
  );

  if (!changed) {
    throw new Error('Outcome edge not found.');
  }

  return {
    yamlText: stringifyRoot(rootObj),
    changed: safeOldOutcome !== safeNewOutcome,
  };
}

export function deleteFlowEdge({ yamlText, fromStep, toStep, outcome = null }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, fromStep, 'Source step');

  const safeOutcome = outcome ? String(outcome).trim() : null;
  const before = flow.length;

  workflow.flow = normalizeFlow(
    flow.filter((edge) => {
      if (!edge || typeof edge !== 'object') {
        return false;
      }

      const sameFrom = edge.from === fromStep;
      const sameTo = edge.to === toStep;
      const sameOutcome = (edge.on ? String(edge.on).trim() : null) === safeOutcome;

      return !(sameFrom && sameTo && sameOutcome);
    }),
  );

  if (workflow.flow.length === before) {
    throw new Error('Flow edge not found.');
  }

  return {
    yamlText: stringifyRoot(rootObj),
    mode: 'deleted',
  };
}
