import { parseDocument, stringify } from 'yaml';

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

function getStepObj(rootObj, stepId) {
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);

  if (!Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`Step "${stepId}" not found.`);
  }

  const stepObj = steps[stepId];
  if (!stepObj || typeof stepObj !== 'object') {
    throw new Error(`Step "${stepId}" is invalid.`);
  }

  return stepObj;
}

function ensureStepType(stepObj, expectedType, stepId) {
  if (String(stepObj.type || '') !== expectedType) {
    throw new Error(`Step "${stepId}" is not a ${expectedType} step.`);
  }
}

function ensureObject(value, createFallback = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return createFallback;
  }
  return value;
}

function ensureArray(value, createFallback = []) {
  if (!Array.isArray(value)) {
    return createFallback;
  }
  return value;
}

function normalizeVarsTarget(rawValue, fallback = 'vars.value') {
  const trimmed = String(rawValue || '').trim();
  if (!trimmed) {
    return fallback;
  }
  return trimmed.startsWith('vars.') ? trimmed : `vars.${trimmed}`;
}

function parseScalarValue(rawValue) {
  const text = String(rawValue ?? '').trim();

  if (!text) {
    return '';
  }

  if (text === 'true') {
    return true;
  }
  if (text === 'false') {
    return false;
  }
  if (text === 'null') {
    return null;
  }

  if (/^-?\d+$/.test(text)) {
    return Number.parseInt(text, 10);
  }

  if (/^-?\d+\.\d+$/.test(text)) {
    return Number.parseFloat(text);
  }

  return text;
}

function parseMultilineArgs(rawValue) {
  return String(rawValue || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseScalarValue);
}

function nextUniqueKey(existingKeys, baseKey) {
  if (!existingKeys.includes(baseKey)) {
    return baseKey;
  }

  let i = 2;
  while (existingKeys.includes(`${baseKey}_${i}`)) {
    i += 1;
  }
  return `${baseKey}_${i}`;
}

export function addLogicCase({
  yamlText,
  stepId,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  stepObj.cases = ensureArray(stepObj.cases, []);
  stepObj.cases.push({
    when: {
      compare: {
        left: '${vars.value}',
        op: '==',
        right: '',
      },
    },
    outcome: 'ok',
  });

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeLogicCase({
  yamlText,
  stepId,
  index,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  stepObj.cases = ensureArray(stepObj.cases, []);
  if (index < 0 || index >= stepObj.cases.length) {
    throw new Error(`Logic case ${index} not found.`);
  }

  stepObj.cases.splice(index, 1);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function setLogicCaseOutcome({
  yamlText,
  stepId,
  index,
  outcome,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  stepObj.cases = ensureArray(stepObj.cases, []);
  if (index < 0 || index >= stepObj.cases.length) {
    throw new Error(`Logic case ${index} not found.`);
  }

  const caseObj = stepObj.cases[index];
  if (!caseObj || typeof caseObj !== 'object') {
    throw new Error(`Logic case ${index} is invalid.`);
  }

  caseObj.outcome = String(outcome || '').trim() || 'ok';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function setLogicDefaultOutcome({
  yamlText,
  stepId,
  outcome,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  stepObj.default = String(outcome || '').trim() || 'fail';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addWebhookCaptureRule({
  yamlText,
  stepId,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'webhook', stepId);

  stepObj.capture = ensureObject(stepObj.capture, {});
  const existingKeys = Object.keys(stepObj.capture);
  const targetKey = nextUniqueKey(existingKeys, 'vars.http_status');
  stepObj.capture[targetKey] = 'status_code';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function updateWebhookCaptureRule({
  yamlText,
  stepId,
  oldTarget,
  newTarget,
  source,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'webhook', stepId);

  stepObj.capture = ensureObject(stepObj.capture, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.capture, oldTarget)) {
    throw new Error(`Capture rule "${oldTarget}" not found.`);
  }

  const normalizedTarget = normalizeVarsTarget(newTarget, oldTarget);
  const normalizedSource = String(source || '').trim() || 'status_code';

  if (normalizedTarget !== oldTarget) {
    delete stepObj.capture[oldTarget];
  }

  stepObj.capture[normalizedTarget] = normalizedSource;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeWebhookCaptureRule({
  yamlText,
  stepId,
  target,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'webhook', stepId);

  stepObj.capture = ensureObject(stepObj.capture, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.capture, target)) {
    return {
      yamlText,
      changed: false,
    };
  }

  delete stepObj.capture[target];

  if (!Object.keys(stepObj.capture).length) {
    delete stepObj.capture;
  }

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addComputeAssignment({
  yamlText,
  stepId,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'compute', stepId);

  stepObj.set = ensureObject(stepObj.set, {});
  const targetKey = nextUniqueKey(Object.keys(stepObj.set), 'vars.result');
  stepObj.set[targetKey] = {
    add: ['${vars.a}', 1],
  };

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function updateComputeAssignment({
  yamlText,
  stepId,
  oldTarget,
  newTarget,
  operator,
  argsText,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'compute', stepId);

  stepObj.set = ensureObject(stepObj.set, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.set, oldTarget)) {
    throw new Error(`Compute assignment "${oldTarget}" not found.`);
  }

  const normalizedTarget = normalizeVarsTarget(newTarget, oldTarget);
  const normalizedOperator = String(operator || '').trim() || 'add';
  const parsedArgs = parseMultilineArgs(argsText);

  if (normalizedTarget !== oldTarget) {
    delete stepObj.set[oldTarget];
  }

  stepObj.set[normalizedTarget] = {
    [normalizedOperator]: parsedArgs.length ? parsedArgs : ['${vars.a}', 1],
  };

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeComputeAssignment({
  yamlText,
  stepId,
  target,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'compute', stepId);

  stepObj.set = ensureObject(stepObj.set, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.set, target)) {
    return {
      yamlText,
      changed: false,
    };
  }

  delete stepObj.set[target];

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addSetVarEntry({
  yamlText,
  stepId,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'set', stepId);

  stepObj.vars = ensureObject(stepObj.vars, {});
  const key = nextUniqueKey(Object.keys(stepObj.vars), 'result');
  stepObj.vars[key] = 'value';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function updateSetVarEntry({
  yamlText,
  stepId,
  oldKey,
  newKey,
  value,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'set', stepId);

  stepObj.vars = ensureObject(stepObj.vars, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.vars, oldKey)) {
    throw new Error(`Var entry "${oldKey}" not found.`);
  }

  const normalizedKey = String(newKey || '').trim() || oldKey;
  if (normalizedKey !== oldKey) {
    delete stepObj.vars[oldKey];
  }

  stepObj.vars[normalizedKey] = parseScalarValue(value);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeSetVarEntry({
  yamlText,
  stepId,
  key,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'set', stepId);

  stepObj.vars = ensureObject(stepObj.vars, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.vars, key)) {
    return {
      yamlText,
      changed: false,
    };
  }

  delete stepObj.vars[key];

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}