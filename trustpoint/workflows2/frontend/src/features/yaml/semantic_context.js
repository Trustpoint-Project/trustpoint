import { isMap, isSeq, parseDocument } from 'yaml';

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

function getLineInfoAtOffset(yamlText, offset) {
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

function findDeepestPath(node, offset, path = []) {
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

function deriveTextPathAtOffset(yamlText, offset) {
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

function pathToString(path) {
  if (!Array.isArray(path) || !path.length) {
    return '(root)';
  }

  let out = '';
  for (const part of path) {
    if (typeof part === 'number') {
      out += `[${part}]`;
    } else if (!out) {
      out = part;
    } else {
      out += `.${part}`;
    }
  }
  return out;
}

function resolveArea(path) {
  if (!Array.isArray(path) || !path.length) {
    return 'root';
  }

  if (path[0] === 'trigger') {
    if (path.length === 1) return 'trigger';
    if (path[1] === 'on') return 'trigger.on';
    if (path[1] === 'sources') return 'trigger.sources';
    return 'trigger';
  }

  if (path[0] === 'apply') {
    return path.length === 1 ? 'apply' : 'apply.item';
  }

  if (path[0] === 'workflow') {
    if (path.length === 1) return 'workflow';
    if (path[1] === 'start') return 'workflow.start';
    if (path[1] === 'steps') {
      if (path.length === 2) return 'workflow.steps';
      if (path.length === 3) return 'workflow.steps.item';
      return 'workflow.steps.field';
    }
    if (path[1] === 'flow') {
      return path.length === 2 ? 'workflow.flow' : 'workflow.flow.item';
    }
    return 'workflow';
  }

  return 'root';
}

function areaTitle(area) {
  switch (area) {
    case 'root':
      return 'Workflow document';
    case 'trigger':
      return 'Trigger block';
    case 'trigger.on':
      return 'Trigger selection';
    case 'trigger.sources':
      return 'Trigger sources';
    case 'apply':
      return 'Apply block';
    case 'apply.item':
      return 'Apply rule';
    case 'workflow':
      return 'Workflow block';
    case 'workflow.start':
      return 'Workflow start';
    case 'workflow.steps':
      return 'Workflow steps';
    case 'workflow.steps.item':
      return 'Workflow step';
    case 'workflow.steps.field':
      return 'Step field';
    case 'workflow.flow':
      return 'Workflow flow';
    case 'workflow.flow.item':
      return 'Flow edge';
    case 'invalid':
      return 'Invalid YAML';
    default:
      return 'Workflow document';
  }
}

function addKnownVarName(targetSet, rawName) {
  if (typeof rawName !== 'string') {
    return;
  }

  const name = rawName.trim();
  if (!name) {
    return;
  }

  targetSet.add(name);
}

function extractKnownVarNames(rootObj) {
  const known = new Set();

  const stepsObj =
    rootObj?.workflow?.steps && typeof rootObj.workflow.steps === 'object'
      ? rootObj.workflow.steps
      : {};

  for (const stepObj of Object.values(stepsObj)) {
    if (!stepObj || typeof stepObj !== 'object') {
      continue;
    }

    if (stepObj.type === 'set' && stepObj.vars && typeof stepObj.vars === 'object') {
      for (const key of Object.keys(stepObj.vars)) {
        addKnownVarName(known, key);
      }
    }

    if (stepObj.type === 'compute' && stepObj.set && typeof stepObj.set === 'object') {
      for (const key of Object.keys(stepObj.set)) {
        if (key.startsWith('vars.')) {
          addKnownVarName(known, key.slice(5));
        }
      }
    }

    if (stepObj.type === 'webhook' && stepObj.capture && typeof stepObj.capture === 'object') {
      for (const key of Object.keys(stepObj.capture)) {
        if (key.startsWith('vars.')) {
          addKnownVarName(known, key.slice(5));
        }
      }
    }
  }

  return Array.from(known).sort((a, b) => a.localeCompare(b));
}

function uniqStrings(values) {
  const out = [];
  const seen = new Set();

  for (const value of values || []) {
    if (typeof value !== 'string' || !value.trim()) {
      continue;
    }
    const s = value.trim();
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }

  return out;
}

function extractStepOutcomes(stepObj) {
  if (!stepObj || typeof stepObj !== 'object') {
    return [];
  }

  if (stepObj.type === 'logic') {
    const cases = Array.isArray(stepObj.cases) ? stepObj.cases : [];
    const caseOutcomes = cases
      .map((item) => (item && typeof item === 'object' ? item.outcome : null))
      .filter((value) => typeof value === 'string');

    const defaultOutcome = typeof stepObj.default === 'string' ? [stepObj.default] : [];
    return uniqStrings([...caseOutcomes, ...defaultOutcome]);
  }

  if (stepObj.type === 'approval') {
    return uniqStrings([
      stepObj.approved_outcome,
      stepObj.rejected_outcome,
    ]);
  }

  return [];
}

function extractStepSummaries(rootObj) {
  const stepsObj =
    rootObj?.workflow?.steps && typeof rootObj.workflow.steps === 'object'
      ? rootObj.workflow.steps
      : {};

  return Object.entries(stepsObj).map(([stepId, stepObj]) => ({
    id: stepId,
    type: stepObj && typeof stepObj === 'object' && typeof stepObj.type === 'string' ? stepObj.type : null,
    outcomes: extractStepOutcomes(stepObj),
  }));
}

export function parseYamlStatus(yamlText) {
  try {
    const doc = parseDocument(yamlText, {
      prettyErrors: true,
    });

    if (doc.errors.length) {
      return {
        ok: false,
        message: String(doc.errors[0]),
      };
    }

    if (doc.warnings.length) {
      return {
        ok: true,
        message: `Parsed with warning: ${String(doc.warnings[0])}`,
      };
    }

    return {
      ok: true,
      message: 'YAML parsed successfully.',
    };
  } catch (err) {
    return {
      ok: false,
      message: err instanceof Error ? err.message : String(err),
    };
  }
}

export function deriveSemanticContext(yamlText, offset) {
  try {
    const doc = parseDocument(yamlText, {
      prettyErrors: true,
      keepSourceTokens: true,
    });

    if (doc.errors.length) {
      return {
        ok: false,
        area: 'invalid',
        title: areaTitle('invalid'),
        path: [],
        pathLabel: '(invalid)',
        parseMessage: String(doc.errors[0]),
        triggerKey: null,
        stepIds: [],
        stepSummaries: [],
        currentStartStep: null,
        stepId: null,
        stepType: null,
        fieldKey: null,
        stepFieldKeys: [],
        knownVarNames: [],
        flowFieldKey: null,
        currentFlowItem: null,
        currentFlowOutcomeOptions: [],
      };
    }

    const rootObj = doc.toJS() || {};
    const astPath = findDeepestPath(doc.contents, offset, []) || [];
    const textPath = deriveTextPathAtOffset(yamlText, offset);
    const lineInfo = getLineInfoAtOffset(yamlText, offset);

    let path = astPath;
    if (lineInfo.isBlank || lineInfo.isComment || textPath.length > astPath.length) {
      path = textPath;
    }

    const area = resolveArea(path);

    const triggerKey =
      typeof rootObj?.trigger?.on === 'string' ? rootObj.trigger.on : null;

    const stepsObj =
      rootObj?.workflow?.steps && typeof rootObj.workflow.steps === 'object'
        ? rootObj.workflow.steps
        : {};

    const stepIds = Object.keys(stepsObj);
    const stepSummaries = extractStepSummaries(rootObj);

    const currentStartStep =
      typeof rootObj?.workflow?.start === 'string'
        ? rootObj.workflow.start
        : null;

    const stepId =
      path[0] === 'workflow' && path[1] === 'steps' && typeof path[2] === 'string'
        ? path[2]
        : null;

    const stepObj =
      stepId && stepsObj[stepId] && typeof stepsObj[stepId] === 'object'
        ? stepsObj[stepId]
        : null;

    const stepType =
      stepObj && typeof stepObj.type === 'string'
        ? stepObj.type
        : null;

    const fieldKey =
      path[0] === 'workflow' &&
      path[1] === 'steps' &&
      typeof path[2] === 'string' &&
      typeof path[3] === 'string'
        ? path[3]
        : null;

    const stepFieldKeys =
      stepObj && typeof stepObj === 'object'
        ? Object.keys(stepObj)
        : [];

    const flowArray =
      Array.isArray(rootObj?.workflow?.flow) ? rootObj.workflow.flow : [];

    const flowItemIndex =
      path[0] === 'workflow' && path[1] === 'flow' && typeof path[2] === 'number'
        ? path[2]
        : null;

    const currentFlowItem =
      flowItemIndex !== null &&
      flowArray[flowItemIndex] &&
      typeof flowArray[flowItemIndex] === 'object'
        ? flowArray[flowItemIndex]
        : null;

    const flowFieldKey =
      path[0] === 'workflow' &&
      path[1] === 'flow' &&
      typeof path[3] === 'string'
        ? path[3]
        : null;

    const allKnownOutcomes = uniqStrings(
      stepSummaries.flatMap((item) => item.outcomes || []),
    );

    const currentFlowFrom =
      currentFlowItem && typeof currentFlowItem.from === 'string'
        ? currentFlowItem.from
        : null;

    const currentFlowOutcomeOptions =
      currentFlowFrom
        ? (
            stepSummaries.find((item) => item.id === currentFlowFrom)?.outcomes ||
            allKnownOutcomes
          )
        : allKnownOutcomes;

    return {
      ok: true,
      area,
      title: areaTitle(area),
      path,
      pathLabel: pathToString(path),
      parseMessage: 'YAML parsed successfully.',
      triggerKey,
      stepIds,
      stepSummaries,
      currentStartStep,
      stepId,
      stepType,
      fieldKey,
      stepFieldKeys,
      knownVarNames: extractKnownVarNames(rootObj),
      flowFieldKey,
      currentFlowItem,
      currentFlowOutcomeOptions,
    };
  } catch (err) {
    return {
      ok: false,
      area: 'invalid',
      title: areaTitle('invalid'),
      path: [],
      pathLabel: '(invalid)',
      parseMessage: err instanceof Error ? err.message : String(err),
      triggerKey: null,
      stepIds: [],
      stepSummaries: [],
      currentStartStep: null,
      stepId: null,
      stepType: null,
      fieldKey: null,
      stepFieldKeys: [],
      knownVarNames: [],
      flowFieldKey: null,
      currentFlowItem: null,
      currentFlowOutcomeOptions: [],
    };
  }
}