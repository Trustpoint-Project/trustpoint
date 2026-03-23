import { parseDocument, stringify } from 'yaml';

const SUPPORTED_OPERATORS = new Set(['exists', 'compare', 'not', 'and', 'or']);

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

function getApplyArray(rootObj) {
  if (!Array.isArray(rootObj.apply)) {
    rootObj.apply = [];
  }
  return rootObj.apply;
}

function getConditionOperator(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return null;
  }

  for (const key of ['exists', 'compare', 'not', 'and', 'or']) {
    if (Object.prototype.hasOwnProperty.call(node, key)) {
      return key;
    }
  }

  return null;
}

function createCompareScaffold() {
  return {
    compare: {
      left: '${vars.value}',
      op: '==',
      right: '',
    },
  };
}

function createExistsScaffold() {
  return {
    exists: '${vars.value}',
  };
}

function createConditionScaffold(operatorName) {
  const op = String(operatorName || '').trim();

  if (!SUPPORTED_OPERATORS.has(op)) {
    throw new Error(`Unsupported apply operator "${operatorName}".`);
  }

  if (op === 'exists') {
    return createExistsScaffold();
  }

  if (op === 'compare') {
    return createCompareScaffold();
  }

  if (op === 'not') {
    return {
      not: createCompareScaffold(),
    };
  }

  if (op === 'and') {
    return {
      and: [createCompareScaffold()],
    };
  }

  if (op === 'or') {
    return {
      or: [createCompareScaffold()],
    };
  }

  return createCompareScaffold();
}

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
    const op = getConditionOperator(current);

    if (op === 'not') {
      if (step !== 0) {
        throw new Error('Invalid child path for "not".');
      }
      current = current.not;
      continue;
    }

    if (op === 'and' || op === 'or') {
      const children = Array.isArray(current[op]) ? current[op] : [];
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

  const parentPath = path.slice(0, -1);
  const childIndex = path[path.length - 1];
  const parent = getNodeAtPath(rootNode, parentPath);
  const parentOp = getConditionOperator(parent);

  if (parentOp === 'not') {
    if (childIndex !== 0) {
      throw new Error('Invalid child path for "not".');
    }
    parent.not = nextNode;
    return rootNode;
  }

  if (parentOp === 'and' || parentOp === 'or') {
    const children = Array.isArray(parent[parentOp]) ? parent[parentOp] : [];
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

  const parentPath = path.slice(0, -1);
  const childIndex = path[path.length - 1];
  const parent = getNodeAtPath(rootNode, parentPath);
  const parentOp = getConditionOperator(parent);

  if (parentOp === 'not') {
    if (childIndex !== 0) {
      throw new Error('Invalid child path for "not".');
    }
    parent.not = createCompareScaffold();
    return rootNode;
  }

  if (parentOp === 'and' || parentOp === 'or') {
    const children = Array.isArray(parent[parentOp]) ? parent[parentOp] : [];
    if (childIndex < 0 || childIndex >= children.length) {
      throw new Error('Apply child path out of bounds.');
    }

    children.splice(childIndex, 1);

    if (!children.length) {
      children.push(createCompareScaffold());
    }

    return rootNode;
  }

  throw new Error('Parent node cannot contain nested conditions.');
}

function parseYamlValue(rawValue, label) {
  const text = String(rawValue ?? '');

  if (!text.trim()) {
    return '';
  }

  const doc = parseDocument(text, { prettyErrors: true });
  if (doc.errors.length) {
    throw new Error(`${label}: ${String(doc.errors[0])}`);
  }

  return doc.toJS();
}

export function addApplyRule({
  yamlText,
  operator = 'compare',
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);

  apply.push(createConditionScaffold(operator));

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
    ruleIndex: apply.length - 1,
  };
}

export function removeApplyRule({
  yamlText,
  ruleIndex,
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index } = getRule(apply, ruleIndex);

  apply.splice(index, 1);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function setApplyNodeOperator({
  yamlText,
  ruleIndex,
  path,
  operator,
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const parsedPath = parsePath(path);
  const nextNode = createConditionScaffold(operator);

  apply[index] = replaceNodeAtPath(rule, parsedPath, nextNode);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveApplyExists({
  yamlText,
  ruleIndex,
  path,
  value,
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const parsedPath = parsePath(path);
  const node = getNodeAtPath(rule, parsedPath);

  if (getConditionOperator(node) !== 'exists') {
    throw new Error('Selected apply node is not an "exists" condition.');
  }

  node.exists = String(value || '').trim() || '${vars.value}';
  apply[index] = rule;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function saveApplyCompare({
  yamlText,
  ruleIndex,
  path,
  left,
  op,
  right,
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const parsedPath = parsePath(path);
  const node = getNodeAtPath(rule, parsedPath);

  if (getConditionOperator(node) !== 'compare') {
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

export function addApplyChild({
  yamlText,
  ruleIndex,
  path,
  operator = 'compare',
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const parsedPath = parsePath(path);
  const node = getNodeAtPath(rule, parsedPath);
  const nodeOp = getConditionOperator(node);
  const child = createConditionScaffold(operator);

  if (nodeOp === 'not') {
    node.not = child;
    apply[index] = rule;
    return {
      yamlText: stringifyRoot(rootObj),
      changed: true,
    };
  }

  if (nodeOp === 'and' || nodeOp === 'or') {
    if (!Array.isArray(node[nodeOp])) {
      node[nodeOp] = [];
    }
    node[nodeOp].push(child);
    apply[index] = rule;
    return {
      yamlText: stringifyRoot(rootObj),
      changed: true,
    };
  }

  throw new Error(`Operator "${nodeOp || 'unknown'}" cannot contain nested conditions.`);
}

export function removeApplyChild({
  yamlText,
  ruleIndex,
  path,
}) {
  const rootObj = parseRoot(yamlText);
  const apply = getApplyArray(rootObj);
  const { index, rule } = getRule(apply, ruleIndex);
  const parsedPath = parsePath(path);

  apply[index] = removeNodeAtPath(rule, parsedPath);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}