import { normalizeVarsTarget, parseMultilineArgs, parseScalarValue } from '../value_utils.js';
import {
  ensureArray,
  ensureObject,
  ensureStepType,
  getStep,
  parseRoot,
  stringifyRoot,
} from '../yaml_document.js';
import { createConditionNode } from '../condition_tree.js';
import { makeUniqueKey } from '../catalog_metadata.js';

function getTypedStep(rootObj, stepId, expectedType) {
  const stepObj = getStep(rootObj, stepId);
  ensureStepType(stepObj, expectedType, stepId);
  return stepObj;
}

function ensureUniqueKey(target, key, label) {
  if (Object.prototype.hasOwnProperty.call(target, key)) {
    throw new Error(`Duplicate ${label} "${key}".`);
  }
}

function normalizeSetVarKey(rawValue, fallback = 'vars.result') {
  return normalizeVarsTarget(rawValue, fallback);
}

export function addLogicCase({ yamlText, stepId }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'logic');

  stepObj.cases = ensureArray(stepObj.cases, []);
  stepObj.cases.push({
    when: createConditionNode('compare'),
    outcome: 'ok',
  });

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeLogicCase({ yamlText, stepId, index }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'logic');

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

export function setLogicCaseOutcome({ yamlText, stepId, index, outcome }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'logic');

  stepObj.cases = ensureArray(stepObj.cases, []);
  if (index < 0 || index >= stepObj.cases.length) {
    throw new Error(`Logic case ${index} not found.`);
  }

  const caseObj = ensureObject(stepObj.cases[index], {});
  stepObj.cases[index] = caseObj;
  caseObj.outcome = String(outcome || '').trim() || 'ok';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function setLogicDefaultOutcome({ yamlText, stepId, outcome }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'logic');

  stepObj.default = String(outcome || '').trim() || 'fail';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function replaceLogicStepContent({ yamlText, stepId, cases, defaultOutcome }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'logic');

  stepObj.cases = ensureArray(cases, []).map((item) => ({
    when: item?.when && typeof item.when === 'object' && !Array.isArray(item.when)
      ? item.when
      : createConditionNode('compare'),
    outcome: String(item?.outcome || '').trim() || 'ok',
  }));
  stepObj.default = String(defaultOutcome || '').trim() || 'fail';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addWebhookCaptureRule({ yamlText, stepId }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'webhook');

  stepObj.capture = ensureObject(stepObj.capture, {});
  const targetKey = makeUniqueKey(Object.keys(stepObj.capture), 'vars.http_status');
  stepObj.capture[targetKey] = 'status_code';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function updateWebhookCaptureRule({ yamlText, stepId, oldTarget, newTarget, source }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'webhook');

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

export function removeWebhookCaptureRule({ yamlText, stepId, target }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'webhook');

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

export function replaceWebhookCaptureRules({ yamlText, stepId, rows }) {
  if (!Array.isArray(rows) || !rows.length) {
    return {
      yamlText,
      changed: false,
    };
  }

  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'webhook');
  const nextCapture = {};

  for (const row of rows) {
    const target = normalizeVarsTarget(row?.target, 'vars.http_status');
    const source = String(row?.source || '').trim() || 'status_code';
    ensureUniqueKey(nextCapture, target, 'capture target');
    nextCapture[target] = source;
  }

  stepObj.capture = nextCapture;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addComputeAssignment({ yamlText, stepId }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'compute');

  stepObj.set = ensureObject(stepObj.set, {});
  const targetKey = makeUniqueKey(Object.keys(stepObj.set), 'vars.result');
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
  const stepObj = getTypedStep(rootObj, stepId, 'compute');

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

export function removeComputeAssignment({ yamlText, stepId, target }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'compute');

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

export function replaceComputeAssignments({ yamlText, stepId, rows }) {
  if (!Array.isArray(rows) || !rows.length) {
    return {
      yamlText,
      changed: false,
    };
  }

  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'compute');
  const nextAssignments = {};

  for (const row of rows) {
    const target = normalizeVarsTarget(row?.target, 'vars.result');
    const operator = String(row?.operator || '').trim() || 'add';
    const args = parseMultilineArgs(row?.argsText);
    ensureUniqueKey(nextAssignments, target, 'compute target');
    nextAssignments[target] = {
      [operator]: args.length ? args : ['${vars.a}', 1],
    };
  }

  stepObj.set = nextAssignments;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addSetVarEntry({ yamlText, stepId }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'set');

  stepObj.vars = ensureObject(stepObj.vars, {});
  const key = makeUniqueKey(
    Object.keys(stepObj.vars).map((item) => normalizeSetVarKey(item, 'vars.result')),
    'vars.result',
  );
  stepObj.vars[key] = 'value';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function updateSetVarEntry({ yamlText, stepId, oldKey, newKey, value }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'set');

  stepObj.vars = ensureObject(stepObj.vars, {});
  if (!Object.prototype.hasOwnProperty.call(stepObj.vars, oldKey)) {
    throw new Error(`Var entry "${oldKey}" not found.`);
  }

  const normalizedKey = normalizeSetVarKey(newKey, oldKey || 'vars.result');
  const existingKeys = Object.keys(stepObj.vars)
    .filter((key) => key !== oldKey)
    .map((key) => normalizeSetVarKey(key, 'vars.result'));
  if (existingKeys.includes(normalizedKey)) {
    throw new Error(`Duplicate vars entry "${normalizedKey}".`);
  }

  if (normalizedKey !== oldKey) {
    delete stepObj.vars[oldKey];
  }

  stepObj.vars[normalizedKey] = parseScalarValue(value);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeSetVarEntry({ yamlText, stepId, key }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'set');

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

export function replaceSetVarEntries({ yamlText, stepId, rows }) {
  if (!Array.isArray(rows) || !rows.length) {
    return {
      yamlText,
      changed: false,
    };
  }

  const rootObj = parseRoot(yamlText);
  const stepObj = getTypedStep(rootObj, stepId, 'set');
  const nextVars = {};

  for (const row of rows) {
    const key = normalizeSetVarKey(row?.key, 'vars.result');
    ensureUniqueKey(nextVars, key, 'vars entry');
    nextVars[key] = parseScalarValue(row?.value);
  }

  stepObj.vars = nextVars;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}
