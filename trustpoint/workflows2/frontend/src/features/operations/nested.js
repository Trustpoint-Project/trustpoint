import { stringify } from 'yaml';

function countIndent(lineText) {
  const match = String(lineText || '').match(/^(\s*)/);
  return match ? match[1].length : 0;
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

function getLineInfo(text, offset) {
  const { lineStart, lineEnd, lineText } = getLineBounds(text, offset);
  return {
    lineStart,
    lineEnd,
    lineText,
    indent: countIndent(lineText),
    trimmed: lineText.trim(),
  };
}

function indentBlock(blockText, indentSpaces) {
  const prefix = ' '.repeat(indentSpaces);
  return blockText
    .split('\n')
    .map((line) => (line ? `${prefix}${line}` : line))
    .join('\n');
}

function insertAboveLine(yamlText, lineStart, blockText) {
  return yamlText.slice(0, lineStart) + blockText + '\n' + yamlText.slice(lineStart);
}

function insertBelowLine(yamlText, lineEnd, blockText) {
  return yamlText.slice(0, lineEnd) + '\n' + blockText + yamlText.slice(lineEnd);
}

function replaceLine(yamlText, lineStart, lineEnd, blockText) {
  return yamlText.slice(0, lineStart) + blockText + yamlText.slice(lineEnd);
}

function isBareYamlKeyLine(trimmed) {
  return /^[A-Za-z_][A-Za-z0-9_.-]*\s*:\s*$/.test(trimmed);
}

function insertStructuredBlockAtTarget(yamlText, target, blockObject, childIndentDelta = 2) {
  const rawBlock = stringify(blockObject, {
    indent: 2,
    lineWidth: 0,
  }).trimEnd();

  if (target.trimmed === '' || target.trimmed.startsWith('#')) {
    const block = indentBlock(rawBlock, target.indent);
    return replaceLine(yamlText, target.lineStart, target.lineEnd, block);
  }

  if (isBareYamlKeyLine(target.trimmed)) {
    const block = indentBlock(rawBlock, target.indent + childIndentDelta);
    return insertBelowLine(yamlText, target.lineEnd, block);
  }

  const block = indentBlock(rawBlock, target.indent);
  return insertAboveLine(yamlText, target.lineStart, block);
}

function findFieldLineInCurrentStep(yamlText, stepId, fieldKey) {
  const lines = yamlText.split('\n');
  let offset = 0;
  let insideStep = false;
  let stepIndent = null;

  for (const line of lines) {
    const trimmed = line.trim();
    const indent = countIndent(line);
    const lineStart = offset;
    const lineEnd = offset + line.length;

    if (!insideStep) {
      if (new RegExp(`^\\s*${stepId}\\s*:\\s*$`).test(line)) {
        insideStep = true;
        stepIndent = indent;
      }
      offset = lineEnd + 1;
      continue;
    }

    if (trimmed && !trimmed.startsWith('#') && indent <= stepIndent) {
      return null;
    }

    if (new RegExp(`^\\s*${fieldKey}\\s*:\\s*(.*)$`).test(line)) {
      return {
        lineStart,
        lineEnd,
        lineText: line,
        indent,
        trimmed,
      };
    }

    offset = lineEnd + 1;
  }

  return null;
}

function resolveStepFieldTarget(yamlText, cursorOffset, context, fieldKey) {
  let target = getLineInfo(yamlText, cursorOffset);

  if (context?.stepId && context?.fieldKey !== fieldKey) {
    const fieldLine = findFieldLineInCurrentStep(yamlText, context.stepId, fieldKey);
    if (fieldLine) {
      target = fieldLine;
    }
  }

  return target;
}

function getLinesWithOffsets(yamlText) {
  const rawLines = yamlText.split('\n');
  const lines = [];
  let offset = 0;

  for (let i = 0; i < rawLines.length; i += 1) {
    const line = rawLines[i];
    const start = offset;
    const end = start + line.length;
    const hasTrailingNewline = i < rawLines.length - 1;

    lines.push({
      index: i,
      text: line,
      trimmed: line.trim(),
      indent: countIndent(line),
      start,
      end,
      fullEnd: hasTrailingNewline ? end + 1 : end,
    });

    offset = hasTrailingNewline ? end + 1 : end;
  }

  return lines;
}

function findWorkflowFlowBlock(yamlText) {
  const lines = getLinesWithOffsets(yamlText);

  let workflowLine = null;
  for (const line of lines) {
    if (line.trimmed === 'workflow:') {
      workflowLine = line;
      break;
    }
  }

  if (!workflowLine) {
    return null;
  }

  let flowLine = null;
  let flowIsInlineEmpty = false;

  for (const line of lines.slice(workflowLine.index + 1)) {
    if (line.trimmed && !line.trimmed.startsWith('#') && line.indent <= workflowLine.indent) {
      break;
    }

    if (line.indent > workflowLine.indent && /^flow:\s*(\[\s*\])?\s*$/.test(line.trimmed)) {
      flowLine = line;
      flowIsInlineEmpty = /^flow:\s*\[\s*\]\s*$/.test(line.trimmed);
      break;
    }
  }

  if (!flowLine) {
    return null;
  }

  let blockEnd = yamlText.length;

  for (const line of lines.slice(flowLine.index + 1)) {
    if (line.trimmed && !line.trimmed.startsWith('#') && line.indent <= flowLine.indent) {
      blockEnd = line.start;
      break;
    }
  }

  return {
    flowLine,
    flowIsInlineEmpty,
    blockEnd,
  };
}

function appendFlowItem(yamlText, itemObject) {
  const flowBlock = findWorkflowFlowBlock(yamlText);
  if (!flowBlock) {
    throw new Error('Could not find workflow.flow block.');
  }

  const rawItem = stringify([itemObject], {
    indent: 2,
    lineWidth: 0,
  }).trimEnd();

  const itemIndent = flowBlock.flowLine.indent + 2;
  const itemText = indentBlock(rawItem, itemIndent);

  if (flowBlock.flowIsInlineEmpty) {
    const replacement =
      `${' '.repeat(flowBlock.flowLine.indent)}flow:\n` +
      `${itemText}`;

    return replaceLine(
      yamlText,
      flowBlock.flowLine.start,
      flowBlock.flowLine.end,
      replacement,
    );
  }

  const before = yamlText.slice(0, flowBlock.blockEnd);
  const after = yamlText.slice(flowBlock.blockEnd);

  const needsLeadingNewline = !before.endsWith('\n');
  const insertion =
    `${needsLeadingNewline ? '\n' : ''}${itemText}\n`;

  return before + insertion + after;
}

function findStepSummary(context, stepId) {
  return (context?.stepSummaries || []).find((item) => item.id === stepId) || null;
}

function chooseFromStep(context, explicitFrom = null, { requireOutcomes = false } = {}) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];
  const stepSummaries = Array.isArray(context?.stepSummaries) ? context.stepSummaries : [];

  if (explicitFrom && stepIds.includes(explicitFrom)) {
    if (!requireOutcomes || (findStepSummary(context, explicitFrom)?.outcomes || []).length) {
      return explicitFrom;
    }
  }

  const currentFrom =
    context?.currentFlowItem && typeof context.currentFlowItem.from === 'string'
      ? context.currentFlowItem.from
      : null;

  if (currentFrom && stepIds.includes(currentFrom)) {
    if (!requireOutcomes || (findStepSummary(context, currentFrom)?.outcomes || []).length) {
      return currentFrom;
    }
  }

  if (context?.currentStartStep && stepIds.includes(context.currentStartStep)) {
    if (!requireOutcomes || (findStepSummary(context, context.currentStartStep)?.outcomes || []).length) {
      return context.currentStartStep;
    }
  }

  if (requireOutcomes) {
    const firstOutcomeStep = stepSummaries.find(
      (item) => Array.isArray(item.outcomes) && item.outcomes.length > 0,
    );
    if (firstOutcomeStep) {
      return firstOutcomeStep.id;
    }
  }

  if (stepIds.length) {
    return stepIds[0];
  }

  throw new Error('No steps available in workflow.');
}

function chooseToStep(context, fromStep, explicitTo = null, { allowEnd = true } = {}) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];

  if (explicitTo) {
    return explicitTo;
  }

  const currentTo =
    context?.currentFlowItem && typeof context.currentFlowItem.to === 'string'
      ? context.currentFlowItem.to
      : null;

  if (currentTo && currentTo !== fromStep) {
    return currentTo;
  }

  const firstOther = stepIds.find((stepId) => stepId !== fromStep);
  if (firstOther) {
    return firstOther;
  }

  return allowEnd ? '$end' : fromStep;
}

function chooseOutcome(context, fromStep, explicitOutcome = null) {
  if (explicitOutcome && explicitOutcome.trim()) {
    return explicitOutcome.trim();
  }

  const fromSummary = findStepSummary(context, fromStep);
  const outcomes = Array.isArray(fromSummary?.outcomes) ? fromSummary.outcomes : [];
  if (outcomes.length) {
    return outcomes[0];
  }

  const known = Array.isArray(context?.currentFlowOutcomeOptions)
    ? context.currentFlowOutcomeOptions
    : [];
  if (known.length) {
    return known[0];
  }

  return 'outcome';
}

export function insertLogicCase({ yamlText, cursorOffset, context }) {
  if (!context?.stepId) {
    throw new Error('No current logic step selected.');
  }

  const target = resolveStepFieldTarget(yamlText, cursorOffset, context, 'cases');

  const blockObject = [
    {
      when: {
        compare: {
          left: '${vars.status}',
          op: '==',
          right: 200,
        },
      },
      outcome: 'ok',
    },
  ];

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}

export function insertComputeAssignment({ yamlText, cursorOffset, context }) {
  if (!context?.stepId) {
    throw new Error('No current compute step selected.');
  }

  const target = resolveStepFieldTarget(yamlText, cursorOffset, context, 'set');

  const blockObject = {
    'vars.result': '${add(vars.a, 1)}',
  };

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}

export function insertWebhookCaptureRule({ yamlText, cursorOffset, context }) {
  if (!context?.stepId) {
    throw new Error('No current webhook step selected.');
  }

  if (!Array.isArray(context.stepFieldKeys) || !context.stepFieldKeys.includes('capture')) {
    throw new Error('This step has no capture field yet. Add the optional "capture" field first.');
  }

  const target = resolveStepFieldTarget(yamlText, cursorOffset, context, 'capture');

  const blockObject = {
    'vars.http_status': 'status_code',
  };

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}

export function insertFlowLinearEdge({
  yamlText,
  context,
  fromStep = null,
  toStep = null,
}) {
  const resolvedFrom = chooseFromStep(context, fromStep, { requireOutcomes: false });
  const resolvedTo = chooseToStep(context, resolvedFrom, toStep, { allowEnd: true });

  return appendFlowItem(yamlText, {
    from: resolvedFrom,
    to: resolvedTo,
  });
}

export function insertFlowOutcomeEdge({
  yamlText,
  context,
  fromStep = null,
  toStep = null,
  outcome = null,
}) {
  const resolvedFrom = chooseFromStep(context, fromStep, { requireOutcomes: true });
  const resolvedTo = chooseToStep(context, resolvedFrom, toStep, { allowEnd: true });
  const resolvedOutcome = chooseOutcome(context, resolvedFrom, outcome);

  return appendFlowItem(yamlText, {
    from: resolvedFrom,
    on: resolvedOutcome,
    to: resolvedTo,
  });
}