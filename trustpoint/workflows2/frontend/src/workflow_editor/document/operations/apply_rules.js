import { CONDITION_OPERATORS, createConditionNode } from '../condition_tree.js';
import { parseYamlValue } from '../value_utils.js';
import { getApplyArray, parseRoot, stringifyRoot } from '../yaml_document.js';

const SUPPORTED_OPERATORS = new Set(CONDITION_OPERATORS);

function parsePath(rawPath) {
  if (!rawPath) {
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(rawPath);
  } catch {
    throw new Error('Invalid apply condition path.');
  }

  if (!Array.isArray(parsed) || !parsed.every((item) => Number.isInteger(item) && item >= 0)) {
    throw new Error('Invalid apply condition path.');
  }

  return parsed;
}

function getApplyNodeOperator(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return null;
  }

  for (const key of CONDITION_OPERATORS) {
    if (Object.prototype.hasOwnProperty.call(node, key)) {
      return key;
    }
  }

  return null;
}

function createApplyNode(operatorName) {
  const operator = String(operatorName || '').trim();
  if (!SUPPORTED_OPERATORS.has(operator)) {
    throw new Error(`Unsupported apply operator "${operatorName}".`);
  }

  return createConditionNode(operator);
}

function getRule(apply, ruleIndex) {
  const index = Number.parseInt(String(ruleIndex), 10);
  if (!Number.isInteger(index) || index < 0 || index >= apply.length) {
    throw new Error(`Apply rule ${ruleIndex} not found.`);
  }

  return {
    index,
    rule: apply[index],
  };
}

function getNodeAtPath(rootNode, path) {
  let current = rootNode;

  for (const step of path) {
    const operator = getApplyNodeOperator(current);

    if (operator === 'not') {
      if (step !== 0) {
        throw new Error('Invalid child path for "not".');
      }
      current = current.not;
      continue;
    }

    if (operator === 'and' || operator === 'or') {
      const children = Array.isArray(current[operator]) ? current[operator] : [];
      if (step < 0 || step >= children.length) {
        throw new Error('Apply child path out of bounds.');
      }
      current = children[step];
      continue;
    }

    throw new Error('This apply condition node cannot have children.');
  }

  return current;
}

function replaceNodeAtPath(rootNode, path, nextNode) {
  if (!path.length) {
    return nextNode;
  }

  const parent = getNodeAtPath(rootNode, path.slice(0, -1));
  const childIndex = path[path.length - 1];
  const parentOperator = getApplyNodeOperator(parent);

  if (parentOperator === 'not') {
    if (childIndex !== 0) {
      throw new Error('Invalid child path for "not".');
    }
    parent.not = nextNode;
    return rootNode;
  }

  if (parentOperator === 'and' || parentOperator === 'or') {
    const children = Array.isArray(parent[parentOperator]) ? parent[parentOperator] : [];
    if (childIndex < 0 || childIndex >= children.length) {
      throw new Error('Apply child path out of bounds.');
    }
    children[childIndex] = nextNode;
    return rootNode;
  }

  throw new Error('Parent node cannot contain nested conditions.');
}

function removeNodeAtPath(rootNode, path) {
  if (!path.length) {
    throw new Error('Cannot remove root node with child removal.');
  }

  const parent = getNodeAtPath(rootNode, path.slice(0, -1));
  const childIndex = path[path.length - 1];
  const parentOperator = getApplyNodeOperator(parent);

  if (parentOperator === 'not') {
    if (childIndex !== 0) {
      throw new Error('Invalid child path for "not".');
    }
    parent.not = createConditionNode('compare');
    return rootNode;
  }

  if (parentOperator === 'and' || parentOperator === 'or') {
    const children = Array.isArray(parent[parentOperator]) ? parent[parentOperator] : [];
    if (childIndex < 0 || childIndex >= children.length) {
      throw new Error('Apply child path out of bounds.');
    }

    children.splice(childIndex, 1);
    if (!children.length) {
      children.push(createConditionNode('compare'));
    }
    return rootNode;
  }

  throw new Error('Parent node cannot contain nested conditions.');
}

export function addApplyRule({ yamlText, operator = 'compare' }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);

  apply.push(createApplyNode(operator));

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
    ruleIndex: apply.length - 1,
  };
}

export function removeApplyRule({ yamlText, ruleIndex }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index } = getRule(apply, ruleIndex);

  apply.splice(index, 1);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function setApplyNodeOperator({ yamlText, ruleIndex, path, operator }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);

  apply[index] = replaceNodeAtPath(rule, parsePath(path), createApplyNode(operator));

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveApplyExists({ yamlText, ruleIndex, path, value }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const node = getNodeAtPath(rule, parsePath(path));

  if (getApplyNodeOperator(node) !== 'exists') {
    throw new Error('Selected apply node is not an "exists" condition.');
  }

  node.exists = String(value || '').trim() || '${vars.value}';
  apply[index] = rule;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveApplyCompare({ yamlText, ruleIndex, path, left, op, right }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const node = getNodeAtPath(rule, parsePath(path));

  if (getApplyNodeOperator(node) !== 'compare') {
    throw new Error('Selected apply node is not a "compare" condition.');
  }

  node.compare = {
    left: String(left || '').trim() || '${vars.value}',
    op: String(op || '').trim() || '==',
    right: parseYamlValue(right, 'compare.right'),
  };
  apply[index] = rule;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addApplyChild({ yamlText, ruleIndex, path, operator = 'compare' }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const node = getNodeAtPath(rule, parsePath(path));
  const child = createApplyNode(operator);
  const nodeOperator = getApplyNodeOperator(node);

  if (nodeOperator === 'not') {
    node.not = child;
  } else if (nodeOperator === 'and' || nodeOperator === 'or') {
    if (!Array.isArray(node[nodeOperator])) {
      node[nodeOperator] = [];
    }
    node[nodeOperator].push(child);
  } else {
    throw new Error(`Operator "${nodeOperator || 'unknown'}" cannot contain nested conditions.`);
  }

  apply[index] = rule;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function removeApplyChild({ yamlText, ruleIndex, path }) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);

  apply[index] = removeNodeAtPath(rule, parsePath(path));

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}
