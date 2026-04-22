import { findStepSpec } from '../catalog_metadata.js';
import {
  appendFlowItem,
  findFieldLineInCurrentStep,
  getLineBounds,
  getLineInfo,
  insertStructuredBlockAtTarget,
  resolveStepFieldTarget,
} from '../text_insertions.js';

function conditionScaffoldForKey(conditionKey, catalog) {
  const operators = catalog?.dsl?.conditions?.operators || [];
  const spec = operators.find((item) => item.key === conditionKey);
  if (!spec || !spec.scaffold) {
    throw new Error(`No condition scaffold found for "${conditionKey}".`);
  }

  return spec.scaffold;
}

function computeArgsForOperator(operatorName) {
  switch (operatorName) {
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return ['${vars.a}', 1];
    case 'min':
    case 'max':
      return ['${vars.a}', '${vars.b}'];
    case 'round':
    case 'int':
    case 'float':
      return ['${vars.a}'];
    default:
      return ['${vars.a}', 1];
  }
}

function findStepSummary(context, stepId) {
  return (context?.stepSummaries || []).find((item) => item.id === stepId) || null;
}

function chooseFromStep(context, explicitFrom = null, { requireOutcomes = false } = {}) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];
  const stepSummaries = Array.isArray(context?.stepSummaries) ? context.stepSummaries : [];

  if (explicitFrom && stepIds.includes(explicitFrom)) {
    if (!requireOutcomes || (findStepSummary(context, explicitFrom)?.outcomes || []).length) {
      return explicitFrom;
    }
  }

  const currentFrom =
    context?.currentFlowItem && typeof context.currentFlowItem.from === 'string'
      ? context.currentFlowItem.from
      : null;

  if (currentFrom && stepIds.includes(currentFrom)) {
    if (!requireOutcomes || (findStepSummary(context, currentFrom)?.outcomes || []).length) {
      return currentFrom;
    }
  }

  if (context?.currentStartStep && stepIds.includes(context.currentStartStep)) {
    if (!requireOutcomes || (findStepSummary(context, context.currentStartStep)?.outcomes || []).length) {
      return context.currentStartStep;
    }
  }

  if (requireOutcomes) {
    const firstOutcomeStep = stepSummaries.find((item) => Array.isArray(item.outcomes) && item.outcomes.length);
    if (firstOutcomeStep) {
      return firstOutcomeStep.id;
    }
  }

  if (stepIds.length) {
    return stepIds[0];
  }

  throw new Error('No steps available in workflow.');
}

function chooseToStep(context, fromStep, explicitTo = null, { allowEnd = true } = {}) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];

  if (explicitTo) {
    return explicitTo;
  }

  const currentTo =
    context?.currentFlowItem && typeof context.currentFlowItem.to === 'string'
      ? context.currentFlowItem.to
      : null;

  if (currentTo && currentTo !== fromStep) {
    return currentTo;
  }

  const firstOther = stepIds.find((stepId) => stepId !== fromStep);
  if (firstOther) {
    return firstOther;
  }

  return allowEnd ? '$end' : fromStep;
}

function chooseOutcome(context, fromStep, explicitOutcome = null) {
  if (explicitOutcome && explicitOutcome.trim()) {
    return explicitOutcome.trim();
  }

  const fromSummary = findStepSummary(context, fromStep);
  const outcomes = Array.isArray(fromSummary?.outcomes) ? fromSummary.outcomes : [];
  if (outcomes.length) {
    return outcomes[0];
  }

  const knownOutcomes = Array.isArray(context?.currentFlowOutcomeOptions)
    ? context.currentFlowOutcomeOptions
    : [];

  if (knownOutcomes.length) {
    return knownOutcomes[0];
  }

  return 'outcome';
}

export function setCurrentScalarValue({ yamlText, cursorOffset, rawValue }) {
  const { lineStart, lineEnd, lineText } = getLineBounds(yamlText, cursorOffset);
  const match = lineText.match(/^(\s*[A-Za-z_][A-Za-z0-9_.-]*\s*:\s*)(.*)$/);

  if (!match) {
    throw new Error('Current line is not a simple YAML key/value line.');
  }

  return yamlText.slice(0, lineStart) + `${match[1]}${rawValue}` + yamlText.slice(lineEnd);
}

export function insertConditionOperator({
  yamlText,
  cursorOffset,
  catalog,
  conditionKey,
  mode,
  context,
}) {
  const scaffold = conditionScaffoldForKey(conditionKey, catalog);

  let blockObject = scaffold;
  if (mode === 'apply-item') {
    blockObject = [scaffold];
  }

  let target = getLineInfo(yamlText, cursorOffset);

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}

export function insertComputeOperator({ yamlText, cursorOffset, operatorName, context }) {
  const blockObject = {
    'vars.result': {
      [operatorName]: computeArgsForOperator(operatorName),
    },
  };

  let target = getLineInfo(yamlText, cursorOffset);
  if (context?.stepId && context?.fieldKey !== 'set') {
    const setLine = findFieldLineInCurrentStep(yamlText, context.stepId, 'set');
    if (setLine) {
      target = setLine;
    }
  }

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}

export function insertComputeAssignment({ yamlText, cursorOffset, context }) {
  if (!context?.stepId) {
    throw new Error('No current compute step selected.');
  }

  return insertStructuredBlockAtTarget(
    yamlText,
    resolveStepFieldTarget(yamlText, cursorOffset, context, 'set'),
    {
      'vars.result': '${add(vars.a, 1)}',
    },
    2,
  );
}

export function insertWebhookCaptureRule({ yamlText, cursorOffset, context }) {
  if (!context?.stepId) {
    throw new Error('No current webhook step selected.');
  }

  if (!Array.isArray(context.stepFieldKeys) || !context.stepFieldKeys.includes('capture')) {
    throw new Error('This step has no capture field yet. Add the optional "capture" field first.');
  }

  return insertStructuredBlockAtTarget(
    yamlText,
    resolveStepFieldTarget(yamlText, cursorOffset, context, 'capture'),
    {
      'vars.http_status': 'status_code',
    },
    2,
  );
}

export function insertFlowLinearEdge({ yamlText, context, fromStep = null, toStep = null }) {
  const resolvedFrom = chooseFromStep(context, fromStep, { requireOutcomes: false });
  const resolvedTo = chooseToStep(context, resolvedFrom, toStep, { allowEnd: true });

  return appendFlowItem(yamlText, {
    from: resolvedFrom,
    to: resolvedTo,
  });
}

export function insertFlowOutcomeEdge({
  yamlText,
  context,
  fromStep = null,
  toStep = null,
  outcome = null,
}) {
  const resolvedFrom = chooseFromStep(context, fromStep, { requireOutcomes: true });
  const resolvedTo = chooseToStep(context, resolvedFrom, toStep, { allowEnd: true });
  const resolvedOutcome = chooseOutcome(context, resolvedFrom, outcome);

  return appendFlowItem(yamlText, {
    from: resolvedFrom,
    on: resolvedOutcome,
    to: resolvedTo,
  });
}

export function getGuideStepSpec(catalog, stepType) {
  return findStepSpec(catalog, stepType);
}
