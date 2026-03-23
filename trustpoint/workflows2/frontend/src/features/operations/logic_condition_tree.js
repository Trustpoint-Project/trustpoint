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

function getLogicCase(rootObj, stepId, caseIndex) {
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);

  if (!Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`Step "${stepId}" not found.`);
  }

  const stepObj = steps[stepId];
  if (!stepObj || typeof stepObj !== 'object') {
    throw new Error(`Step "${stepId}" is invalid.`);
  }

  if (String(stepObj.type || '') !== 'logic') {
    throw new Error(`Step "${stepId}" is not a logic step.`);
  }

  if (!Array.isArray(stepObj.cases)) {
    stepObj.cases = [];
  }

  if (caseIndex < 0 || caseIndex >= stepObj.cases.length) {
    throw new Error(`Logic case ${caseIndex} not found.`);
  }

  const caseObj = stepObj.cases[caseIndex];
  if (!caseObj || typeof caseObj !== 'object') {
    throw new Error(`Logic case ${caseIndex} is invalid.`);
  }

  if (!caseObj.when || typeof caseObj.when !== 'object' || Array.isArray(caseObj.when)) {
    caseObj.when = makeDefaultConditionNode('compare');
  }

  return caseObj;
}

function makeDefaultConditionNode(kind = 'compare') {
  switch (kind) {
    case 'exists':
      return {
        exists: '${vars.value}',
      };

    case 'not':
      return {
        not: makeDefaultConditionNode('compare'),
      };

    case 'and':
      return {
        and: [makeDefaultConditionNode('compare')],
      };

    case 'or':
      return {
        or: [makeDefaultConditionNode('compare')],
      };

    case 'compare':
    default:
      return {
        compare: {
          left: '${vars.value}',
          op: '==',
          right: '',
        },
      };
  }
}

function normalizePath(path) {
  if (!Array.isArray(path)) {
    return [];
  }

  return path.map((part) => {
    if (typeof part === 'number') {
      return part;
    }

    if (typeof part === 'string' && /^\d+$/.test(part)) {
      return Number.parseInt(part, 10);
    }

    return part;
  });
}

function getNodeAtPath(rootNode, rawPath) {
  const path = normalizePath(rawPath);
  let node = rootNode;

  for (const part of path) {
    if (node == null) {
      return null;
    }
    node = node[part];
  }

  return node;
}

function setNodeAtPath(caseObj, rawPath, nextNode) {
  const path = normalizePath(rawPath);

  if (!path.length) {
    caseObj.when = nextNode;
    return;
  }

  const parent = getNodeAtPath(caseObj.when, path.slice(0, -1));
  const last = path[path.length - 1];

  if (parent == null) {
    throw new Error('Condition path not found.');
  }

  parent[last] = nextNode;
}

function removeNodeAtPath(caseObj, rawPath) {
  const path = normalizePath(rawPath);

  if (!path.length) {
    caseObj.when = makeDefaultConditionNode('compare');
    return;
  }

  const parent = getNodeAtPath(caseObj.when, path.slice(0, -1));
  const last = path[path.length - 1];

  if (parent == null) {
    throw new Error('Condition path not found.');
  }

  if (Array.isArray(parent) && typeof last === 'number') {
    parent.splice(last, 1);

    if (!parent.length) {
      parent.push(makeDefaultConditionNode('compare'));
    }
    return;
  }

  parent[last] = makeDefaultConditionNode('compare');
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

function getConditionKind(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return 'compare';
  }

  if (Object.prototype.hasOwnProperty.call(node, 'compare')) {
    return 'compare';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'exists')) {
    return 'exists';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'not')) {
    return 'not';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'and')) {
    return 'and';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'or')) {
    return 'or';
  }

  return 'compare';
}

export function setLogicConditionNodeKind({
  yamlText,
  stepId,
  caseIndex,
  path,
  kind,
}) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);
  const normalizedKind = String(kind || '').trim() || 'compare';

  setNodeAtPath(caseObj, path, makeDefaultConditionNode(normalizedKind));

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveLogicCompareNode({
  yamlText,
  stepId,
  caseIndex,
  path,
  left,
  op,
  right,
}) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);

  setNodeAtPath(caseObj, path, {
    compare: {
      left: String(left || '').trim() || '${vars.value}',
      op: String(op || '').trim() || '==',
      right: parseScalarValue(right),
    },
  });

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveLogicExistsNode({
  yamlText,
  stepId,
  caseIndex,
  path,
  value,
}) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);

  setNodeAtPath(caseObj, path, {
    exists: String(value || '').trim() || '${vars.value}',
  });

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addLogicConditionChild({
  yamlText,
  stepId,
  caseIndex,
  path,
}) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);
  const node = getNodeAtPath(caseObj.when, path);

  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    throw new Error('Condition node not found.');
  }

  const kind = getConditionKind(node);

  if (kind !== 'and' && kind !== 'or') {
    throw new Error('Nested conditions can only be added to "and" or "or" nodes.');
  }

  if (!Array.isArray(node[kind])) {
    node[kind] = [];
  }

  node[kind].push(makeDefaultConditionNode('compare'));

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeLogicConditionNode({
  yamlText,
  stepId,
  caseIndex,
  path,
}) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);

  removeNodeAtPath(caseObj, path);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}