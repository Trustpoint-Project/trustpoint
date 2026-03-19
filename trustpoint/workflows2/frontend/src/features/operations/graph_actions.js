import { parseDocument, stringify } from 'yaml';

const END_TARGETS = new Set(['$end', '$reject']);

function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function uniqStrings(values) {
  const out = [];
  const seen = new Set();

  for (const value of values || []) {
    if (typeof value !== 'string') {
      continue;
    }
    const s = value.trim();
    if (!s || seen.has(s)) {
      continue;
    }
    seen.add(s);
    out.push(s);
  }

  return out;
}

function normalizeStepBase(stepType) {
  return `${String(stepType || 'step')
    .trim()
    .replaceAll(/[^a-zA-Z0-9_]+/g, '_')
    .replaceAll(/^_+|_+$/g, '') || 'step'}_step`;
}

function makeUniqueStepId(existingIds, base) {
  if (!existingIds.includes(base)) {
    return base;
  }

  let i = 2;
  while (existingIds.includes(`${base}_${i}`)) {
    i += 1;
  }
  return `${base}_${i}`;
}

function parseRoot(yamlText) {
  const doc = parseDocument(yamlText, { prettyErrors: true });
  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }
  return doc.toJS() || {};
}

function stringifyRoot(rootObj) {
  return stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });
}

function getWorkflow(rootObj) {
  if (!rootObj.workflow || typeof rootObj.workflow !== 'object') {
    throw new Error('workflow block not found');
  }
  return rootObj.workflow;
}

function getSteps(workflow) {
  if (!workflow.steps || typeof workflow.steps !== 'object') {
    workflow.steps = {};
  }
  return workflow.steps;
}

function getFlow(workflow) {
  if (!Array.isArray(workflow.flow)) {
    workflow.flow = [];
  }
  return workflow.flow;
}

function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

function extractStepOutcomes(stepObj) {
  if (!stepObj || typeof stepObj !== 'object') {
    return [];
  }

  if (stepObj.type === 'logic') {
    const cases = Array.isArray(stepObj.cases) ? stepObj.cases : [];
    const caseOutcomes = cases
      .map((item) => (item && typeof item === 'object' ? item.outcome : null))
      .filter((value) => typeof value === 'string');

    const defaultOutcome = typeof stepObj.default === 'string' ? [stepObj.default] : [];
    return uniqStrings([...caseOutcomes, ...defaultOutcome]);
  }

  if (stepObj.type === 'approval') {
    return uniqStrings([
      stepObj.approved_outcome,
      stepObj.rejected_outcome,
    ]);
  }

  return [];
}

function isOutcomeProducingStep(stepObj) {
  return extractStepOutcomes(stepObj).length > 0;
}

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

function ensureOutcomeMappings(flow, stepId, outcomes) {
  const safeOutcomes = uniqStrings(outcomes);

  for (const outcome of safeOutcomes) {
    const existing = flow.find(
      (edge) => edge && typeof edge === 'object' && edge.from === stepId && edge.on === outcome,
    );

    if (!existing) {
      flow.push({
        from: stepId,
        on: outcome,
        to: '$end',
      });
    }
  }
}

function normalizeFlow(flow) {
  const linearSeen = new Set();
  const outcomeSeen = new Set();
  const out = [];

  for (const edge of flow || []) {
    if (!edge || typeof edge !== 'object') {
      continue;
    }

    const from = typeof edge.from === 'string' ? edge.from : null;
    const to = typeof edge.to === 'string' ? edge.to : null;
    const on = typeof edge.on === 'string' ? edge.on : null;

    if (!from || !to) {
      continue;
    }

    if (on) {
      const key = `${from}|${on}`;
      if (outcomeSeen.has(key)) {
        continue;
      }
      outcomeSeen.add(key);
      out.push({ from, on, to });
    } else {
      if (linearSeen.has(from)) {
        continue;
      }
      linearSeen.add(from);
      out.push({ from, to });
    }
  }

  return out;
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
  const flow = getFlow(workflow);

  const stepSpec = findStepSpec(catalog, stepType);
  if (!stepSpec) {
    throw new Error(`Unknown step type "${stepType}".`);
  }

  const existingIds = Object.keys(steps);
  const stepId = makeUniqueStepId(existingIds, normalizeStepBase(stepType));
  const stepObj = deepClone(stepSpec.scaffold || { type: stepType });

  steps[stepId] = stepObj;

  const currentStart = typeof workflow.start === 'string' ? workflow.start : '';
  const startLooksInvalid =
    !currentStart ||
    currentStart.startsWith('__') ||
    !Object.prototype.hasOwnProperty.call(steps, currentStart);

  if (startLooksInvalid) {
    workflow.start = stepId;
  }

  if (isOutcomeProducingStep(stepObj)) {
    ensureOutcomeMappings(flow, stepId, extractStepOutcomes(stepObj));
    workflow.flow = normalizeFlow(flow);
  }

  return {
    yamlText: stringifyRoot(rootObj),
    stepId,
  };
}

export function setStepTitle({ yamlText, stepId, title }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const stepObj = steps[stepId];

  if (!stepObj || typeof stepObj !== 'object') {
    throw new Error(`Step "${stepId}" not found.`);
  }

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

  if (!Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`Step "${stepId}" not found.`);
  }

  const stepIds = Object.keys(steps);
  if (stepIds.length <= 1) {
    throw new Error('Cannot delete the last step.');
  }

  const nextFlow = [];

  for (const edge of flow) {
    if (!edge || typeof edge !== 'object') {
      continue;
    }

    if (edge.from === stepId) {
      continue;
    }

    if (edge.to === stepId) {
      if (typeof edge.on === 'string' && edge.on.trim()) {
        nextFlow.push({
          from: edge.from,
          on: edge.on,
          to: '$end',
        });
      }
      continue;
    }

    nextFlow.push(edge);
  }

  delete steps[stepId];
  workflow.flow = normalizeFlow(nextFlow);

  if (workflow.start === stepId) {
    const remaining = Object.keys(steps);
    workflow.start = remaining[0] || '';
  }

  return {
    yamlText: stringifyRoot(rootObj),
  };
}

export function addLinearFlowEdge({ yamlText, fromStep, toStep }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, fromStep, 'Source step');
  validateTarget(steps, toStep);

  const fromObj = steps[fromStep];
  if (isOutcomeProducingStep(fromObj)) {
    throw new Error(
      `Step "${fromStep}" produces outcomes and requires outcome-based transitions.`,
    );
  }

  const hasOutcomeRoutes = flow.some(
    (edge) => edge && typeof edge === 'object' && edge.from === fromStep && typeof edge.on === 'string',
  );
  if (hasOutcomeRoutes) {
    throw new Error(
      `Step "${fromStep}" already has outcome-based transitions and cannot also have a linear edge.`,
    );
  }

  let updated = false;
  const nextFlow = flow.map((edge) => {
    if (
      edge &&
      typeof edge === 'object' &&
      edge.from === fromStep &&
      (edge.on === undefined || edge.on === null)
    ) {
      updated = true;
      return {
        from: fromStep,
        to: toStep,
      };
    }
    return edge;
  });

  if (!updated) {
    nextFlow.push({
      from: fromStep,
      to: toStep,
    });
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

  const fromObj = steps[fromStep];
  const validOutcomes = extractStepOutcomes(fromObj);

  if (!validOutcomes.length) {
    throw new Error(
      `Step "${fromStep}" does not produce outcomes and cannot have outcome-based transitions.`,
    );
  }

  const safeOutcome = String(outcome || '').trim();
  if (!safeOutcome || !validOutcomes.includes(safeOutcome)) {
    throw new Error(
      `Invalid outcome "${outcome}" for step "${fromStep}".`,
    );
  }

  const hasLinearRoute = flow.some(
    (edge) =>
      edge &&
      typeof edge === 'object' &&
      edge.from === fromStep &&
      (edge.on === undefined || edge.on === null),
  );

  if (hasLinearRoute) {
    throw new Error(
      `Step "${fromStep}" already has a linear transition and cannot also have outcome-based transitions.`,
    );
  }

  let updated = false;
  const nextFlow = flow.map((edge) => {
    if (
      edge &&
      typeof edge === 'object' &&
      edge.from === fromStep &&
      edge.on === safeOutcome
    ) {
      updated = true;
      return {
        from: fromStep,
        on: safeOutcome,
        to: toStep,
      };
    }
    return edge;
  });

  if (!updated) {
    nextFlow.push({
      from: fromStep,
      on: safeOutcome,
      to: toStep,
    });
  }

  ensureOutcomeMappings(nextFlow, fromStep, validOutcomes);
  workflow.flow = normalizeFlow(nextFlow);

  return {
    yamlText: stringifyRoot(rootObj),
  };
}

export function deleteFlowEdge({ yamlText, fromStep, toStep, outcome = null }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);
  const flow = getFlow(workflow);

  validateExistingStep(steps, fromStep, 'Source step');

  const fromObj = steps[fromStep];
  const validOutcomes = extractStepOutcomes(fromObj);
  const safeOutcome = outcome ? String(outcome).trim() : null;

  if (safeOutcome && validOutcomes.includes(safeOutcome)) {
    let changed = false;

    const nextFlow = flow.map((edge) => {
      if (
        edge &&
        typeof edge === 'object' &&
        edge.from === fromStep &&
        edge.on === safeOutcome
      ) {
        changed = true;

        if (edge.to === '$end') {
          return edge;
        }

        return {
          from: fromStep,
          on: safeOutcome,
          to: '$end',
        };
      }
      return edge;
    });

    if (!changed) {
      throw new Error('Flow edge not found.');
    }

    ensureOutcomeMappings(nextFlow, fromStep, validOutcomes);
    workflow.flow = normalizeFlow(nextFlow);

    return {
      yamlText: stringifyRoot(rootObj),
      mode: 'rerouted_to_end',
    };
  }

  const before = flow.length;
  workflow.flow = normalizeFlow(
    flow.filter((edge) => {
      if (!edge || typeof edge !== 'object') {
        return false;
      }

      const sameFrom = edge.from === fromStep;
      const sameTo = edge.to === toStep;
      const sameOutcome = (edge.on || null) === (safeOutcome || null);

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