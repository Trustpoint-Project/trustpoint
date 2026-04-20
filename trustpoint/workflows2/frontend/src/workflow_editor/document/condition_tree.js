export const CONDITION_OPERATORS = ['compare', 'exists', 'not', 'and', 'or'];

export function createConditionNode(kind = 'compare') {
  switch (kind) {
    case 'exists':
      return { exists: '${vars.value}' };
    case 'not':
      return { not: createConditionNode('compare') };
    case 'and':
      return { and: [createConditionNode('compare')] };
    case 'or':
      return { or: [createConditionNode('compare')] };
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

export function getConditionKind(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return 'compare';
  }

  for (const key of CONDITION_OPERATORS) {
    if (Object.prototype.hasOwnProperty.call(node, key)) {
      return key;
    }
  }

  return 'compare';
}

export function encodeConditionPath(path) {
  return JSON.stringify(Array.isArray(path) ? path : []);
}

export function normalizeConditionPath(path) {
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

export function decodeConditionPath(rawPath) {
  try {
    const parsed = JSON.parse(String(rawPath || '[]'));
    return normalizeConditionPath(Array.isArray(parsed) ? parsed : []);
  } catch {
    return [];
  }
}

export function getNodeAtPath(rootNode, rawPath) {
  const path = normalizeConditionPath(rawPath);
  let node = rootNode;

  for (const part of path) {
    if (node == null) {
      return null;
    }

    node = node[part];
  }

  return node;
}

export function setNodeAtPath(rootNode, rawPath, nextNode) {
  const path = normalizeConditionPath(rawPath);
  if (!path.length) {
    return nextNode;
  }

  const parent = getNodeAtPath(rootNode, path.slice(0, -1));
  const leaf = path[path.length - 1];
  if (parent == null) {
    throw new Error('Condition path not found.');
  }

  parent[leaf] = nextNode;
  return rootNode;
}

export function removeNodeAtPath(rootNode, rawPath) {
  const path = normalizeConditionPath(rawPath);
  if (!path.length) {
    return createConditionNode('compare');
  }

  const parent = getNodeAtPath(rootNode, path.slice(0, -1));
  const leaf = path[path.length - 1];
  if (parent == null) {
    throw new Error('Condition path not found.');
  }

  if (Array.isArray(parent) && typeof leaf === 'number') {
    parent.splice(leaf, 1);
    if (!parent.length) {
      parent.push(createConditionNode('compare'));
    }
    return rootNode;
  }

  parent[leaf] = createConditionNode('compare');
  return rootNode;
}
