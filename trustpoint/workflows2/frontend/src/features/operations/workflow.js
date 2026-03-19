import { parseDocument, stringify } from 'yaml';

export function setWorkflowStart({ yamlText, stepId }) {
  const doc = parseDocument(yamlText, { prettyErrors: true });

  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }

  const rootObj = doc.toJS() || {};

  if (!rootObj.workflow || typeof rootObj.workflow !== 'object') {
    throw new Error('workflow block not found');
  }

  if (!rootObj.workflow.steps || typeof rootObj.workflow.steps !== 'object') {
    throw new Error('workflow.steps block not found');
  }

  if (!Object.prototype.hasOwnProperty.call(rootObj.workflow.steps, stepId)) {
    throw new Error(`step "${stepId}" does not exist`);
  }

  if (rootObj.workflow.start === stepId) {
    return {
      yamlText,
      changed: false,
    };
  }

  rootObj.workflow.start = stepId;

  const nextYaml = stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });

  return {
    yamlText: nextYaml,
    changed: true,
  };
}