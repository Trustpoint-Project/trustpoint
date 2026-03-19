export function pathToString(path) {
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

export function resolveArea(path) {
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

export function areaTitle(area) {
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

export function uniqStrings(values) {
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

export function extractKnownVarNames(rootObj) {
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

export function extractStepOutcomes(stepObj) {
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

export function extractStepSummaries(rootObj) {
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