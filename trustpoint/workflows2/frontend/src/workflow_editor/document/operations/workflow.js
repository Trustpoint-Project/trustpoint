import { getSteps, getWorkflow, parseRoot, stringifyRoot } from '../yaml_document.js';

export function setWorkflowStart({ yamlText, stepId }) {
  const rootObj = parseRoot(yamlText);
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow, { create: false });

  if (!Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`step "${stepId}" does not exist`);
  }

  if (workflow.start === stepId) {
    return {
      yamlText,
      changed: false,
    };
  }

  workflow.start = stepId;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}
