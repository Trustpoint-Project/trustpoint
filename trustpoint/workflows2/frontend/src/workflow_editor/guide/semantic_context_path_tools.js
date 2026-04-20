import { isMap, isSeq } from 'yaml';

function getNodeRange(node) {
  if (!node || !Array.isArray(node.range) || node.range.length === 0) {
    return null;
  }

  const start = typeof node.range[0] === 'number' ? node.range[0] : null;
  const endCandidate = node.range[2] ?? node.range[1] ?? node.range[0];
  const end = typeof endCandidate === 'number' ? endCandidate : null;

  if (start === null || end === null) {
    return null;
  }

  return { start, end };
}

function containsOffset(range, offset) {
  return !!range && offset >= range.start && offset <= range.end;
}

function mergeRanges(a, b) {
  if (!a && !b) return null;
  if (!a) return b;
  if (!b) return a;

  return {
    start: Math.min(a.start, b.start),
    end: Math.max(a.end, b.end),
  };
}

function countIndent(line) {
  const match = String(line || '').match(/^(\s*)/);
  return match ? match[1].length : 0;
}

export function getLineInfoAtOffset(yamlText, offset) {
  const safeOffset = Math.max(0, Math.min(offset, yamlText.length));
  const lineStart = yamlText.lastIndexOf('\n', Math.max(0, safeOffset - 1)) + 1;
  const nextNewline = yamlText.indexOf('\n', safeOffset);
  const lineEnd = nextNewline === -1 ? yamlText.length : nextNewline;
  const lineText = yamlText.slice(lineStart, lineEnd);
  const trimmed = lineText.trim();

  return {
    offset: safeOffset,
    lineStart,
    lineEnd,
    lineText,
    trimmed,
    indent: countIndent(lineText),
    isBlank: trimmed === '',
    isComment: trimmed.startsWith('#'),
  };
}

export function findDeepestPath(node, offset, path = []) {
  if (!node) {
    return null;
  }

  const nodeRange = getNodeRange(node);
  if (nodeRange && !containsOffset(nodeRange, offset)) {
    return null;
  }

  if (isMap(node)) {
    for (const pair of node.items || []) {
      const keyNode = pair?.key;
      const valueNode = pair?.value;

      const keyName =
        keyNode && Object.prototype.hasOwnProperty.call(keyNode, 'value')
          ? String(keyNode.value)
          : null;

      const keyRange = getNodeRange(keyNode);
      const valueRange = getNodeRange(valueNode);
      const pairRange = mergeRanges(keyRange, valueRange);

      if (!keyName) {
        continue;
      }

      if (containsOffset(valueRange, offset)) {
        return findDeepestPath(valueNode, offset, [...path, keyName]) ?? [...path, keyName];
      }

      if (containsOffset(keyRange, offset)) {
        return [...path, keyName];
      }

      if (containsOffset(pairRange, offset)) {
        return [...path, keyName];
      }
    }

    return path;
  }

  if (isSeq(node)) {
    for (let i = 0; i < (node.items || []).length; i += 1) {
      const item = node.items[i];
      const itemRange = getNodeRange(item);

      if (containsOffset(itemRange, offset)) {
        return findDeepestPath(item, offset, [...path, i]) ?? [...path, i];
      }
    }

    return path;
  }

  return path;
}

export function deriveTextPathAtOffset(yamlText, offset) {
  const lines = yamlText.split('\n');
  const lineInfo = getLineInfoAtOffset(yamlText, offset);

  let currentLineIndex = 0;
  let runningOffset = 0;
  for (let i = 0; i < lines.length; i += 1) {
    const lineLen = lines[i].length;
    const start = runningOffset;
    const end = runningOffset + lineLen;
    if (lineInfo.offset >= start && lineInfo.offset <= end + 1) {
      currentLineIndex = i;
      break;
    }
    runningOffset = end + 1;
  }

  const stack = [];

  for (let i = 0; i <= currentLineIndex; i += 1) {
    const line = lines[i];
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const indent = countIndent(line);
    const keyMatch = trimmed.match(/^([A-Za-z_][A-Za-z0-9_.-]*)\s*:/);

    if (keyMatch) {
      while (stack.length && indent <= stack[stack.length - 1].indent) {
        stack.pop();
      }

      stack.push({
        indent,
        key: keyMatch[1],
      });
    }
  }

  if (lineInfo.isBlank || lineInfo.isComment) {
    while (stack.length && lineInfo.indent <= stack[stack.length - 1].indent) {
      stack.pop();
    }
  }

  return stack.map((item) => item.key);
}