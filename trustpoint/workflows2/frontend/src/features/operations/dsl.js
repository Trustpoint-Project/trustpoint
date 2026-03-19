import { stringify } from 'yaml';

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function indentBlock(blockText, indentSpaces) {
  const prefix = ' '.repeat(indentSpaces);
  return blockText
    .split('\n')
    .map((line) => (line ? `${prefix}${line}` : line))
    .join('\n');
}

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

function findFieldLineInCurrentStep(yamlText, stepId, fieldKey) {
  const lines = yamlText.split('\n');
  const stepPattern = new RegExp(`^\\s*${escapeRegExp(stepId)}\\s*:\\s*$`);
  const fieldPattern = new RegExp(`^\\s*${escapeRegExp(fieldKey)}\\s*:\\s*(.*)$`);

  let offset = 0;
  let stepIndent = null;
  let insideStep = false;

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

function conditionScaffoldForKey(conditionKey, catalog) {
  const operators = catalog?.dsl?.conditions?.operators || [];
  const spec = operators.find((item) => item.key === conditionKey);
  if (!spec || !spec.scaffold) {
    throw new Error(`No condition scaffold found for "${conditionKey}".`);
  }
  return spec.scaffold;
}

function computeArgsForOperator(op) {
  switch (op) {
    case 'add':
    case 'sub':
    case 'mul':
    case 'div':
      return ['${vars.a}', 1];
    case 'min':
    case 'max':
      return ['${vars.a}', '${vars.b}'];
    case 'round':
    case 'int':
    case 'float':
      return ['${vars.a}'];
    default:
      return ['${vars.a}', 1];
  }
}

function buildExpressionFunctionText(functionName) {
  switch (functionName) {
    case 'add':
      return '${add(vars.a, 1)}';
    case 'sub':
      return '${sub(vars.a, 1)}';
    case 'mul':
      return '${mul(vars.a, 2)}';
    case 'div':
      return '${div(vars.a, 2)}';
    case 'min':
      return '${min(vars.a, vars.b)}';
    case 'max':
      return '${max(vars.a, vars.b)}';
    case 'round':
      return '${round(vars.a)}';
    case 'int':
      return '${int(vars.a)}';
    case 'float':
      return '${float(vars.a)}';
    case 'str':
      return '${str(vars.value)}';
    case 'lower':
      return '${lower(vars.value)}';
    case 'upper':
      return '${upper(vars.value)}';
    case 'concat':
      return '${concat(vars.a, vars.b)}';
    case 'json':
      return '${json(event)}';
    default:
      return `\${${functionName}()}`;
  }
}

export function buildExpressionFunctionInsertion(functionName) {
  return buildExpressionFunctionText(functionName);
}

export function setCurrentScalarValue({ yamlText, cursorOffset, rawValue }) {
  const { lineStart, lineEnd, lineText } = getLineBounds(yamlText, cursorOffset);
  const match = lineText.match(/^(\s*[A-Za-z_][A-Za-z0-9_.-]*\s*:\s*)(.*)$/);

  if (!match) {
    throw new Error('Current line is not a simple YAML key/value line.');
  }

  const nextLine = `${match[1]}${rawValue}`;
  return yamlText.slice(0, lineStart) + nextLine + yamlText.slice(lineEnd);
}

export function insertConditionOperator({
  yamlText,
  cursorOffset,
  catalog,
  conditionKey,
  mode,
  context,
}) {
  const scaffold = conditionScaffoldForKey(conditionKey, catalog);

  let blockObject;
  if (mode === 'apply-item') {
    blockObject = [scaffold];
  } else if (mode === 'logic-case') {
    blockObject = [
      {
        when: scaffold,
        outcome: 'outcome',
      },
    ];
  } else {
    blockObject = scaffold;
  }

  let target = getLineInfo(yamlText, cursorOffset);

  if (mode === 'logic-case' && context?.stepId && context?.fieldKey !== 'cases') {
    const casesLine = findFieldLineInCurrentStep(yamlText, context.stepId, 'cases');
    if (casesLine) {
      target = casesLine;
    }
  }

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}

export function insertComputeOperator({
  yamlText,
  cursorOffset,
  operatorName,
  context,
}) {
  const blockObject = {
    'vars.result': {
      [operatorName]: computeArgsForOperator(operatorName),
    },
  };

  let target = getLineInfo(yamlText, cursorOffset);

  if (context?.stepId && context?.fieldKey !== 'set') {
    const setLine = findFieldLineInCurrentStep(yamlText, context.stepId, 'set');
    if (setLine) {
      target = setLine;
    }
  }

  return insertStructuredBlockAtTarget(yamlText, target, blockObject, 2);
}