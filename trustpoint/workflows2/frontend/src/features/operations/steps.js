import { parseDocument, stringify } from 'yaml';

function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

function normalizeStepBase(stepType) {
  return `${String(stepType || 'step')
    .trim()
    .replaceAll(/[^a-zA-Z0-9_]+/g, '_')
    .replaceAll(/^_+|_+$/g, '') || 'step'}_step`;
}

function makeUniqueStepId(existingIds, base) {
  if (!existingIds.includes(base)) {
    return base;
  }

  let i = 2;
  while (existingIds.includes(`${base}_${i}`)) {
    i += 1;
  }
  return `${base}_${i}`;
}

function getWorkflowSteps(rootObj) {
  const workflow = rootObj.workflow;
  if (!workflow || typeof workflow !== 'object') {
    throw new Error('workflow block not found');
  }

  if (!workflow.steps || typeof workflow.steps !== 'object') {
    workflow.steps = {};
  }

  return workflow.steps;
}

function indentBlock(blockText, indentSpaces) {
  const prefix = ' '.repeat(indentSpaces);
  return blockText
    .split('\n')
    .map((line) => (line ? `${prefix}${line}` : line))
    .join('\n');
}

function getLineBounds(text, offset) {
  const safeOffset = Math.max(0, Math.min(offset, text.length));
  const lineStart = text.lastIndexOf('\n', Math.max(0, safeOffset - 1)) + 1;
  const nextNewline = text.indexOf('\n', safeOffset);
  const lineEnd = nextNewline === -1 ? text.length : nextNewline;

  return {
    lineStart,
    lineEnd,
    lineText: text.slice(lineStart, lineEnd),
  };
}

function insertBlockAtCursorLine(yamlText, cursorOffset, blockText) {
  const { lineStart, lineEnd, lineText } = getLineBounds(yamlText, cursorOffset);

  if (lineText.trim() === '') {
    return yamlText.slice(0, lineStart) + blockText + yamlText.slice(lineEnd);
  }

  return yamlText.slice(0, lineStart) + blockText + '\n' + yamlText.slice(lineStart);
}

export function setCurrentStepType({ yamlText, catalog, stepId, stepType }) {
  const doc = parseDocument(yamlText, { prettyErrors: true });

  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }

  const rootObj = doc.toJS() || {};
  const steps = getWorkflowSteps(rootObj);
  const stepObj = steps[stepId];

  if (!stepObj || typeof stepObj !== 'object') {
    throw new Error(`step "${stepId}" not found`);
  }

  const stepSpec = findStepSpec(catalog, stepType);
  if (!stepSpec) {
    throw new Error(`unknown step type "${stepType}"`);
  }

  if (stepObj.type === stepType) {
    return {
      yamlText,
      changed: false,
    };
  }

  stepObj.type = stepType;

  const nextYaml = stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });

  return {
    yamlText: nextYaml,
    changed: true,
  };
}

export function addStepFromType({ yamlText, catalog, stepType, cursorOffset }) {
  const doc = parseDocument(yamlText, { prettyErrors: true });

  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }

  const rootObj = doc.toJS() || {};
  const steps = getWorkflowSteps(rootObj);

  const stepSpec = findStepSpec(catalog, stepType);
  if (!stepSpec) {
    throw new Error(`unknown step type "${stepType}"`);
  }

  const existingIds = Object.keys(steps);
  const stepId = makeUniqueStepId(existingIds, normalizeStepBase(stepType));
  const stepObj = deepClone(stepSpec.scaffold || { type: stepType });

  const rawSnippet = stringify(
    { [stepId]: stepObj },
    {
      indent: 2,
      lineWidth: 0,
    },
  ).trimEnd();

  const snippet = indentBlock(rawSnippet, 4);
  const nextYaml = insertBlockAtCursorLine(yamlText, cursorOffset, snippet);

  return {
    yamlText: nextYaml,
    stepId,
  };
}