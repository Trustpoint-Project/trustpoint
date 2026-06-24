import {
  createConditionNode,
  getNodeAtPath,
  removeNodeAtPath,
  setNodeAtPath,
} from '../condition_tree.js';
import { parseScalarValue } from '../value_utils.js';
import {
  ensureArray,
  ensureObject,
  ensureStepType,
  getStep,
  parseRoot,
  stringifyRoot,
} from '../yaml_document.js';

function getLogicCase(rootObj, stepId, caseIndex) {
  const stepObj = getStep(rootObj, stepId);
  ensureStepType(stepObj, 'logic', stepId);

  stepObj.cases = ensureArray(stepObj.cases, []);
  if (caseIndex < 0 || caseIndex >= stepObj.cases.length) {
    throw new Error(`Logic case ${caseIndex} not found.`);
  }

  const caseObj = ensureObject(stepObj.cases[caseIndex], {});
  stepObj.cases[caseIndex] = caseObj;

  if (!caseObj.when || typeof caseObj.when !== 'object' || Array.isArray(caseObj.when)) {
    caseObj.when = createConditionNode('compare');
  }

  return caseObj;
}

export function setLogicConditionNodeKind({ yamlText, stepId, caseIndex, path, kind }) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);
  caseObj.when = setNodeAtPath(caseObj.when, path, createConditionNode(String(kind || '').trim() || 'compare'));

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
  const node = getNodeAtPath(caseObj.when, path);

  if (!node || typeof node !== 'object' || Array.isArray(node) || !Object.prototype.hasOwnProperty.call(node, 'compare')) {
    throw new Error('Selected condition is not a compare node.');
  }

  node.compare = {
    left: String(left || '').trim() || '${vars.value}',
    op: String(op || '').trim() || '==',
    right: parseScalarValue(right),
  };

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveLogicExistsNode({ yamlText, stepId, caseIndex, path, value }) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);
  const node = getNodeAtPath(caseObj.when, path);

  if (!node || typeof node !== 'object' || Array.isArray(node) || !Object.prototype.hasOwnProperty.call(node, 'exists')) {
    throw new Error('Selected condition is not an exists node.');
  }

  node.exists = String(value || '').trim() || '${vars.value}';

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addLogicConditionChild({ yamlText, stepId, caseIndex, path }) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);
  const node = getNodeAtPath(caseObj.when, path);

  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    throw new Error('Condition path not found.');
  }

  if (Object.prototype.hasOwnProperty.call(node, 'not')) {
    node.not = createConditionNode('compare');
  } else if (Object.prototype.hasOwnProperty.call(node, 'and')) {
    node.and = ensureArray(node.and, []);
    node.and.push(createConditionNode('compare'));
  } else if (Object.prototype.hasOwnProperty.call(node, 'or')) {
    node.or = ensureArray(node.or, []);
    node.or.push(createConditionNode('compare'));
  } else {
    throw new Error('Only "not", "and", and "or" conditions can contain children.');
  }

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeLogicConditionNode({ yamlText, stepId, caseIndex, path }) {
  const rootObj = parseRoot(yamlText);
  const caseObj = getLogicCase(rootObj, stepId, caseIndex);
  caseObj.when = removeNodeAtPath(caseObj.when, path);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}
