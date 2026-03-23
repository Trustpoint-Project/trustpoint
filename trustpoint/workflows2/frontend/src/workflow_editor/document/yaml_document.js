import { parseDocument, stringify } from 'yaml';

export function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

export function ensureObject(value, fallback = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return fallback;
  }
  return value;
}

export function ensureArray(value, fallback = []) {
  return Array.isArray(value) ? value : fallback;
}

export function parseRoot(yamlText) {
  const doc = parseDocument(yamlText, { prettyErrors: true });
  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }

  return doc.toJS() || {};
}

export function stringifyRoot(rootObj) {
  return stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });
}

export function getWorkflow(rootObj) {
  if (!rootObj.workflow || typeof rootObj.workflow !== 'object' || Array.isArray(rootObj.workflow)) {
    throw new Error('workflow block not found');
  }

  return rootObj.workflow;
}

export function getSteps(workflow, { create = true } = {}) {
  if (!workflow.steps || typeof workflow.steps !== 'object' || Array.isArray(workflow.steps)) {
    if (!create) {
      throw new Error('workflow.steps block not found');
    }
    workflow.steps = {};
  }

  return workflow.steps;
}

export function getFlow(workflow, { create = true } = {}) {
  if (!Array.isArray(workflow.flow)) {
    if (!create) {
      throw new Error('workflow.flow block not found');
    }
    workflow.flow = [];
  }

  return workflow.flow;
}

export function getApplyArray(rootObj, { create = true } = {}) {
  if (!Array.isArray(rootObj.apply)) {
    if (!create) {
      throw new Error('apply block not found');
    }
    rootObj.apply = [];
  }

  return rootObj.apply;
}

export function getStep(rootObj, stepId) {
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);

  if (!Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`Step "${stepId}" not found.`);
  }

  const stepObj = steps[stepId];
  if (!stepObj || typeof stepObj !== 'object' || Array.isArray(stepObj)) {
    throw new Error(`Step "${stepId}" is invalid.`);
  }

  return stepObj;
}

export function ensureStepType(stepObj, expectedType, stepId) {
  if (String(stepObj.type || '') !== expectedType) {
    throw new Error(`Step "${stepId}" is not a ${expectedType} step.`);
  }
}
