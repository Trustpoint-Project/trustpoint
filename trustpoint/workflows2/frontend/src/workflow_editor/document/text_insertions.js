import { stringify } from 'yaml';

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function countIndent(lineText) {
  const match = String(lineText || '').match(/^(\s*)/);
  return match ? match[1].length : 0;
}

export function indentBlock(blockText, indentSpaces) {
  const prefix = ' '.repeat(indentSpaces);
  return blockText
    .split('\n')
    .map((line) => (line ? `${prefix}${line}` : line))
    .join('\n');
}

export function getLineBounds(text, offset) {
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

export function getLineInfo(text, offset) {
  const { lineStart, lineEnd, lineText } = getLineBounds(text, offset);
  return {
    lineStart,
    lineEnd,
    lineText,
    indent: countIndent(lineText),
    trimmed: lineText.trim(),
  };
}

export function replaceLine(yamlText, lineStart, lineEnd, blockText) {
  return yamlText.slice(0, lineStart) + blockText + yamlText.slice(lineEnd);
}

export function insertAboveLine(yamlText, lineStart, blockText) {
  return yamlText.slice(0, lineStart) + blockText + '\n' + yamlText.slice(lineStart);
}

export function insertBelowLine(yamlText, lineEnd, blockText) {
  return yamlText.slice(0, lineEnd) + '\n' + blockText + yamlText.slice(lineEnd);
}

export function insertBlockAtCursorLine(yamlText, cursorOffset, blockText) {
  const { lineStart, lineEnd, lineText } = getLineBounds(yamlText, cursorOffset);

  if (lineText.trim() === '') {
    return yamlText.slice(0, lineStart) + blockText + yamlText.slice(lineEnd);
  }

  return yamlText.slice(0, lineStart) + blockText + '\n' + yamlText.slice(lineStart);
}

function isBareYamlKeyLine(trimmed) {
  return /^[A-Za-z_][A-Za-z0-9_.-]*\s*:\s*$/.test(trimmed);
}

export function insertStructuredBlockAtTarget(yamlText, target, blockObject, childIndentDelta = 2) {
  const rawBlock = stringify(blockObject, {
    indent: 2,
    lineWidth: 0,
  }).trimEnd();

  if (target.trimmed === '' || target.trimmed.startsWith('#')) {
    return replaceLine(yamlText, target.lineStart, target.lineEnd, indentBlock(rawBlock, target.indent));
  }

  if (isBareYamlKeyLine(target.trimmed)) {
    return insertBelowLine(
      yamlText,
      target.lineEnd,
      indentBlock(rawBlock, target.indent + childIndentDelta),
    );
  }

  return insertAboveLine(yamlText, target.lineStart, indentBlock(rawBlock, target.indent));
}

function getLinesWithOffsets(yamlText) {
  const rawLines = yamlText.split('\n');
  const lines = [];
  let offset = 0;

  for (let index = 0; index < rawLines.length; index += 1) {
    const text = rawLines[index];
    const start = offset;
    const end = start + text.length;
    const hasTrailingNewline = index < rawLines.length - 1;

    lines.push({
      index,
      text,
      trimmed: text.trim(),
      indent: countIndent(text),
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
  const workflowLine = lines.find((line) => line.trimmed === 'workflow:') || null;
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

export function appendFlowItem(yamlText, itemObject) {
  const flowBlock = findWorkflowFlowBlock(yamlText);
  if (!flowBlock) {
    throw new Error('Could not find workflow.flow block.');
  }

  const rawItem = stringify([itemObject], {
    indent: 2,
    lineWidth: 0,
  }).trimEnd();

  const itemText = indentBlock(rawItem, flowBlock.flowLine.indent + 2);

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
  return before + `${needsLeadingNewline ? '\n' : ''}${itemText}\n` + after;
}

export function findFieldLineInCurrentStep(yamlText, stepId, fieldKey) {
  const lines = yamlText.split('\n');
  const stepPattern = new RegExp(`^\\s*${escapeRegExp(stepId)}\\s*:\\s*$`);
  const fieldPattern = new RegExp(`^\\s*${escapeRegExp(fieldKey)}\\s*:\\s*(.*)$`);

  let offset = 0;
  let insideStep = false;
  let stepIndent = null;

  for (const line of lines) {
    const trimmed = line.trim();
    const indent = countIndent(line);
    const lineStart = offset;
    const lineEnd = offset + line.length;

    if (!insideStep) {
      if (stepPattern.test(line)) {
        insideStep = true;
        stepIndent = indent;
      }

      offset = lineEnd + 1;
      continue;
    }

    if (trimmed && !trimmed.startsWith('#') && indent <= stepIndent) {
      return null;
    }

    if (fieldPattern.test(line)) {
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

export function resolveStepFieldTarget(yamlText, cursorOffset, context, fieldKey) {
  let target = getLineInfo(yamlText, cursorOffset);

  if (context?.stepId && context?.fieldKey !== fieldKey) {
    const fieldLine = findFieldLineInCurrentStep(yamlText, context.stepId, fieldKey);
    if (fieldLine) {
      target = fieldLine;
    }
  }

  return target;
}
