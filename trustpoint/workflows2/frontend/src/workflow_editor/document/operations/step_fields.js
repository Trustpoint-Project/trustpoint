import {
  fallbackFieldValue,
  getFieldSpec,
  getStepFieldSpecs,
  isStructuredField,
} from '../catalog_metadata.js';
import { parseStructuredYaml } from '../value_utils.js';
import { getStep, parseRoot, stringifyRoot } from '../yaml_document.js';

function parseFieldValue(rawValue, fieldSpec) {
  if (!fieldSpec) {
    throw new Error('Unknown field.');
  }

  if (Array.isArray(fieldSpec.enum) && fieldSpec.enum.length) {
    return String(rawValue ?? '');
  }

  if (fieldSpec.field_kind === 'int') {
    const text = String(rawValue ?? '').trim();
    if (!text) {
      return null;
    }

    const parsed = Number.parseInt(text, 10);
    if (!Number.isFinite(parsed)) {
      throw new Error(`Invalid integer value for "${fieldSpec.key}".`);
    }

    return parsed;
  }

  if (isStructuredField(fieldSpec)) {
    return parseStructuredYaml(rawValue, fieldSpec.key);
  }

  return String(rawValue ?? '');
}

function getStepFieldContext(rootObj, catalog, stepId) {
  const stepObj = getStep(rootObj, stepId);
  const stepType = String(stepObj.type || '');

  if (!stepType) {
    throw new Error(`step "${stepId}" has no valid type`);
  }

  return {
    stepObj,
    stepType,
  };
}

export function setStepFieldValue({
  yamlText,
  catalog,
  stepId,
  fieldKey,
  rawValue,
}) {
  const rootObj = parseRoot(yamlText);
  const { stepObj, stepType } = getStepFieldContext(rootObj, catalog, stepId);
  const fieldSpec = getFieldSpec(catalog, stepType, fieldKey, { excludeKeys: ['type'] });

  if (!fieldSpec) {
    throw new Error(`Unknown field "${fieldKey}" for step type "${stepType}".`);
  }

  stepObj[fieldKey] = parseFieldValue(rawValue, fieldSpec);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
  };
}

export function addOptionalStepField({
  yamlText,
  catalog,
  stepId,
  fieldKey,
}) {
  const rootObj = parseRoot(yamlText);
  const { stepObj, stepType } = getStepFieldContext(rootObj, catalog, stepId);
  const fieldSpec = getFieldSpec(catalog, stepType, fieldKey, { excludeKeys: ['type'] });

  if (!fieldSpec) {
    throw new Error(`Unknown field "${fieldKey}" for step type "${stepType}".`);
  }

  if (fieldSpec.required) {
    throw new Error(`Field "${fieldKey}" is required and cannot be added as optional.`);
  }

  if (Object.prototype.hasOwnProperty.call(stepObj, fieldKey)) {
    return {
      yamlText,
      changed: false,
      fieldKey,
    };
  }

  stepObj[fieldKey] = fallbackFieldValue(fieldSpec);

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
    fieldKey,
  };
}

export function removeOptionalStepField({
  yamlText,
  catalog,
  stepId,
  fieldKey,
}) {
  const rootObj = parseRoot(yamlText);
  const { stepObj, stepType } = getStepFieldContext(rootObj, catalog, stepId);
  const fieldSpec = getFieldSpec(catalog, stepType, fieldKey, { excludeKeys: ['type'] });

  if (!fieldSpec) {
    throw new Error(`Unknown field "${fieldKey}" for step type "${stepType}".`);
  }

  if (fieldSpec.required) {
    throw new Error(`Field "${fieldKey}" is required and cannot be removed.`);
  }

  if (!Object.prototype.hasOwnProperty.call(stepObj, fieldKey)) {
    return {
      yamlText,
      changed: false,
      fieldKey,
    };
  }

  delete stepObj[fieldKey];

  return {
    yamlText: stringifyRoot(rootObj),
    changed: true,
    fieldKey,
  };
}

export function addMissingRequiredFields({ yamlText, catalog, stepId }) {
  const rootObj = parseRoot(yamlText);
  const { stepObj, stepType } = getStepFieldContext(rootObj, catalog, stepId);
  const requiredFields = getStepFieldSpecs(catalog, stepType, { excludeKeys: ['type'] }).filter(
    (field) => !!field.required,
  );

  const addedKeys = [];
  for (const field of requiredFields) {
    if (Object.prototype.hasOwnProperty.call(stepObj, field.key)) {
      continue;
    }

    stepObj[field.key] = fallbackFieldValue(field);
    addedKeys.push(field.key);
  }

  if (!addedKeys.length) {
    return {
      yamlText,
      addedKeys: [],
    };
  }

  return {
    yamlText: stringifyRoot(rootObj),
    addedKeys,
  };
}

export function addOptionalField(args) {
  const result = addOptionalStepField(args);
  return {
    yamlText: result.yamlText,
    addedKey: result.changed ? result.fieldKey : null,
  };
}
