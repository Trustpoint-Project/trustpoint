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
  if (!workflow.steps || typeof workflow.steps !== 'object' || Array.isArray(workflow.steps)) {
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

function ensureArray(value, fallback = []) {
  return Array.isArray(value) ? value : fallback;
}

function ensureLogicCase(stepObj, index) {
  stepObj.cases = ensureArray(stepObj.cases, []);
  if (index < 0 || index >= stepObj.cases.length) {
    throw new Error(`Logic case ${index} not found.`);
  }

  const item = stepObj.cases[index];
  if (!item || typeof item !== 'object' || Array.isArray(item)) {
    stepObj.cases[index] = {};
  }

  return stepObj.cases[index];
}

function createDefaultCondition(operator = 'compare') {
  if (operator === 'exists') {
    return { exists: '${vars.value}' };
  }

  if (operator === 'not') {
    return {
      not: {
        compare: {
          left: '${vars.value}',
          op: '==',
          right: '',
        },
      },
    };
  }

  if (operator === 'and' || operator === 'or') {
    return {
      [operator]: [
        {
          compare: {
            left: '${vars.value}',
            op: '==',
            right: '',
          },
        },
      ],
    };
  }

  return {
    compare: {
      left: '${vars.value}',
      op: '==',
      right: '',
    },
  };
}

function getCaseConditionRoot(stepObj, index) {
  const caseObj = ensureLogicCase(stepObj, index);

  if (!caseObj.when || typeof caseObj.when !== 'object' || Array.isArray(caseObj.when)) {
    caseObj.when = createDefaultCondition('compare');
  }

  return caseObj.when;
}

function setCaseConditionRoot(stepObj, index, nextRoot) {
  const caseObj = ensureLogicCase(stepObj, index);
  caseObj.when = nextRoot;
}

function parsePath(rawPath) {
  const text = String(rawPath || '').trim();
  if (!text) {
    return [];
  }

  return text.split('.').map((part) => {
    if (/^\d+$/.test(part)) {
      return Number.parseInt(part, 10);
    }
    return part;
  });
}

function getNodeByPath(root, path) {
  let node = root;

  for (const segment of path) {
    if (typeof segment === 'number') {
      if (!Array.isArray(node)) {
        return undefined;
      }
      node = node[segment];
      continue;
    }

    if (!node || typeof node !== 'object' || Array.isArray(node)) {
      return undefined;
    }
    node = node[segment];
  }

  return node;
}

function setNodeByPath(root, path, nextNode) {
  if (!path.length) {
    return nextNode;
  }

  const parentPath = path.slice(0, -1);
  const leaf = path[path.length - 1];
  const parent = getNodeByPath(root, parentPath);

  if (typeof leaf === 'number') {
    if (!Array.isArray(parent)) {
      throw new Error('Invalid condition path.');
    }
    parent[leaf] = nextNode;
    return root;
  }

  if (!parent || typeof parent !== 'object' || Array.isArray(parent)) {
    throw new Error('Invalid condition path.');
  }

  parent[leaf] = nextNode;
  return root;
}

function removeNodeByPath(root, path) {
  if (!path.length) {
    throw new Error('Root condition cannot be removed. Remove the whole case instead.');
  }

  const parentPath = path.slice(0, -1);
  const leaf = path[path.length - 1];
  const parent = getNodeByPath(root, parentPath);

  if (typeof leaf === 'number') {
    if (!Array.isArray(parent)) {
      throw new Error('Invalid condition path.');
    }
    parent.splice(leaf, 1);
    return root;
  }

  if (!parent || typeof parent !== 'object' || Array.isArray(parent)) {
    throw new Error('Invalid condition path.');
  }

  delete parent[leaf];
  return root;
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

function normalizeCompareOperator(rawValue) {
  const op = String(rawValue || '').trim();
  return op || '==';
}

export function setLogicConditionOperator({
  yamlText,
  stepId,
  index,
  path,
  operator,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  const nextOperator = String(operator || '').trim() || 'compare';
  const rootCondition = getCaseConditionRoot(stepObj, index);
  const nextRoot = setNodeByPath(rootCondition, parsePath(path), createDefaultCondition(nextOperator));

  setCaseConditionRoot(stepObj, index, nextRoot);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveLogicCompareCondition({
  yamlText,
  stepId,
  index,
  path,
  left,
  op,
  right,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  const rootCondition = getCaseConditionRoot(stepObj, index);
  const nextRoot = setNodeByPath(rootCondition, parsePath(path), {
    compare: {
      left: parseScalarValue(left),
      op: normalizeCompareOperator(op),
      right: parseScalarValue(right),
    },
  });

  setCaseConditionRoot(stepObj, index, nextRoot);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveLogicExistsCondition({
  yamlText,
  stepId,
  index,
  path,
  value,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  const rootCondition = getCaseConditionRoot(stepObj, index);
  const nextRoot = setNodeByPath(rootCondition, parsePath(path), {
    exists: parseScalarValue(value),
  });

  setCaseConditionRoot(stepObj, index, nextRoot);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addLogicConditionChild({
  yamlText,
  stepId,
  index,
  path,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  const rootCondition = getCaseConditionRoot(stepObj, index);
  const node = getNodeByPath(rootCondition, parsePath(path));

  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    throw new Error('Invalid condition node.');
  }

  const operator = Object.keys(node)[0];
  if (operator !== 'and' && operator !== 'or') {
    throw new Error('Nested conditions can only be added under "and" or "or".');
  }

  if (!Array.isArray(node[operator])) {
    node[operator] = [];
  }

  node[operator].push(createDefaultCondition('compare'));
  setCaseConditionRoot(stepObj, index, rootCondition);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeLogicConditionNode({
  yamlText,
  stepId,
  index,
  path,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  const rootCondition = getCaseConditionRoot(stepObj, index);
  const nextRoot = removeNodeByPath(rootCondition, parsePath(path));

  setCaseConditionRoot(stepObj, index, nextRoot);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}