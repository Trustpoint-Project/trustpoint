import { parseDocument, stringify } from 'yaml';

function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

function getFieldSeed(field) {
  if (field && Object.prototype.hasOwnProperty.call(field, 'scaffold')) {
    return deepClone(field.scaffold);
  }

  if (field && Object.prototype.hasOwnProperty.call(field, 'default')) {
    return deepClone(field.default);
  }

  return null;
}

function getStepContext(rootObj, stepId) {
  const workflow = rootObj.workflow;
  const steps = workflow?.steps;

  if (!workflow || typeof workflow !== 'object') {
    throw new Error('workflow block not found');
  }

  if (!steps || typeof steps !== 'object') {
    throw new Error('workflow.steps block not found');
  }

  const stepObj = steps[stepId];
  if (!stepObj || typeof stepObj !== 'object') {
    throw new Error(`step "${stepId}" not found`);
  }

  const stepType = typeof stepObj.type === 'string' ? stepObj.type : null;
  if (!stepType) {
    throw new Error(`step "${stepId}" has no valid type`);
  }

  return { stepObj, stepType };
}

function getAllFields(catalog, stepType) {
  const stepSpec = findStepSpec(catalog, stepType);
  if (!stepSpec) {
    throw new Error(`no catalog spec found for step type "${stepType}"`);
  }

  const commonFields = catalog?.meta?.common_step_fields || [];
  return [...commonFields, ...(stepSpec.fields || [])];
}

export function addMissingRequiredFields({ yamlText, catalog, stepId }) {
  const doc = parseDocument(yamlText, { prettyErrors: true });

  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }

  const rootObj = doc.toJS() || {};
  const { stepObj, stepType } = getStepContext(rootObj, stepId);
  const requiredFields = getAllFields(catalog, stepType).filter((field) => !!field.required);

  const addedKeys = [];

  for (const field of requiredFields) {
    if (Object.prototype.hasOwnProperty.call(stepObj, field.key)) {
      continue;
    }

    stepObj[field.key] = getFieldSeed(field);
    addedKeys.push(field.key);
  }

  if (!addedKeys.length) {
    return {
      yamlText,
      addedKeys: [],
    };
  }

  const nextYaml = stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });

  return {
    yamlText: nextYaml,
    addedKeys,
  };
}

export function addOptionalField({ yamlText, catalog, stepId, fieldKey }) {
  const doc = parseDocument(yamlText, { prettyErrors: true });

  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }

  const rootObj = doc.toJS() || {};
  const { stepObj, stepType } = getStepContext(rootObj, stepId);
  const optionalFields = getAllFields(catalog, stepType).filter((field) => !field.required);
  const field = optionalFields.find((item) => item.key === fieldKey);

  if (!field) {
    throw new Error(`optional field "${fieldKey}" is not available for step type "${stepType}"`);
  }

  if (Object.prototype.hasOwnProperty.call(stepObj, field.key)) {
    return {
      yamlText,
      addedKey: null,
    };
  }

  stepObj[field.key] = getFieldSeed(field);

  const nextYaml = stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });

  return {
    yamlText: nextYaml,
    addedKey: field.key,
  };
}