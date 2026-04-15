import { findStepSpec } from '../catalog_metadata.js';
import { addStepToWorkflow } from './graph.js';
import { getStep, parseRoot, stringifyRoot } from '../yaml_document.js';

export function setCurrentStepType({ yamlText, catalog, stepId, stepType }) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStep(rootObj, stepId);
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

  if (typeof stepObj.type === 'string' && stepObj.type.trim()) {
    throw new Error(
      `Step "${stepId}" already has type "${stepObj.type}". Change it directly in YAML if you need to convert it.`,
    );
  }

  stepObj.type = stepType;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addStepFromType({ yamlText, catalog, stepType, cursorOffset }) {
  void cursorOffset;
  return addStepToWorkflow({ yamlText, catalog, stepType });
}
