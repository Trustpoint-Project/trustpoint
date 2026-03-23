import { findStepSpec, makeUniqueKey } from '../catalog_metadata.js';
import { indentBlock, insertBlockAtCursorLine } from '../text_insertions.js';
import { deepClone, getStep, getSteps, getWorkflow, parseRoot, stringifyRoot } from '../yaml_document.js';
import { stringify } from 'yaml';

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

  stepObj.type = stepType;

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addStepFromType({ yamlText, catalog, stepType, cursorOffset }) {
  const rootObj = parseRoot(yamlText);
  const steps = getSteps(getWorkflow(rootObj));
  const stepSpec = findStepSpec(catalog, stepType);

  if (!stepSpec) {
    throw new Error(`unknown step type "${stepType}"`);
  }

  const stepId = makeUniqueKey(Object.keys(steps), `${stepType}_step`);
  const stepObj = deepClone(stepSpec.scaffold || { type: stepType });

  const rawSnippet = stringify(
    { [stepId]: stepObj },
    {
      indent: 2,
      lineWidth: 0,
    },
  ).trimEnd();

  return {
    yamlText: insertBlockAtCursorLine(yamlText, cursorOffset, indentBlock(rawSnippet, 4)),
    stepId,
  };
}
