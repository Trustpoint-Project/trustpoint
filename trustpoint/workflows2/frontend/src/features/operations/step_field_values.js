import { parseDocument, stringify } from 'yaml';

function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function parseRoot(yamlText) {
  const doc = parseDocument(yamlText, { prettyErrors: true });
  if (doc.errors.length) {
    throw new Error(String(doc.errors[0]));
  }
  return doc.toJS() || {};
}

function stringifyRoot(rootObj) {
  return stringify(rootObj, {
    indent: 2,
    lineWidth: 0,
  });
}

function getWorkflow(rootObj) {
  if (!rootObj.workflow || typeof rootObj.workflow !== 'object') {
    throw new Error('workflow block not found');
  }
  return rootObj.workflow;
}

function getSteps(workflow) {
  if (!workflow.steps || typeof workflow.steps !== 'object') {
    workflow.steps = {};
  }
  return workflow.steps;
}

function getStepObj(rootObj, stepId) {
  const workflow = getWorkflow(rootObj);
  const steps = getSteps(workflow);

  if (!Object.prototype.hasOwnProperty.call(steps, stepId)) {
    throw new Error(`Step "${stepId}" not found.`);
  }

  const stepObj = steps[stepId];
  if (!stepObj || typeof stepObj !== 'object') {
    throw new Error(`Step "${stepId}" is invalid.`);
  }

  return stepObj;
}

function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

function getFieldSpec(catalog, stepType, fieldKey) {
  const commonFields = (catalog?.meta?.common_step_fields || []).filter(
    (field) => field.key !== 'type',
  );
  const stepSpec = findStepSpec(catalog, stepType);
  const stepFields = stepSpec?.fields || [];
  return [...commonFields, ...stepFields].find((field) => field.key === fieldKey) || null;
}

function isStructuredField(fieldSpec) {
  return [
    'mapping',
    'list',
    'condition',
    'condition_list',
    'capture_mapping',
    'vars_mapping',
    'compute_mapping',
  ].includes(fieldSpec?.field_kind);
}

function fallbackFieldValue(fieldSpec) {
  if (fieldSpec?.scaffold !== null && fieldSpec?.scaffold !== undefined) {
    return deepClone(fieldSpec.scaffold);
  }

  if (fieldSpec?.default !== null && fieldSpec?.default !== undefined) {
    return deepClone(fieldSpec.default);
  }

  if (fieldSpec?.field_kind === 'list') {
    return [];
  }

  if (isStructuredField(fieldSpec)) {
    return null;
  }

  if (fieldSpec?.field_kind === 'int') {
    return 0;
  }

  return '';
}

function parseStructuredYaml(rawValue, fieldKey) {
  const text = String(rawValue || '').trim();
  if (!text) {
    return null;
  }

  const doc = parseDocument(text, { prettyErrors: true });
  if (doc.errors.length) {
    throw new Error(`${fieldKey}: ${String(doc.errors[0])}`);
  }

  return doc.toJS();
}

function parseFieldValue(rawValue, fieldSpec) {
  if (!fieldSpec) {
    throw new Error('Unknown field.');
  }

  if (Array.isArray(fieldSpec.enum) && fieldSpec.enum.length) {
    return String(rawValue ?? '');
  }

  if (fieldSpec.field_kind === 'int') {
    const s = String(rawValue ?? '').trim();
    if (!s) {
      return null;
    }

    const n = Number.parseInt(s, 10);
    if (!Number.isFinite(n)) {
      throw new Error(`Invalid integer value for "${fieldSpec.key}".`);
    }
    return n;
  }

  if (isStructuredField(fieldSpec)) {
    return parseStructuredYaml(rawValue, fieldSpec.key);
  }

  return String(rawValue ?? '');
}

export function setStepFieldValue({
  yamlText,
  catalog,
  stepId,
  fieldKey,
  rawValue,
}) {
  const rootObj = parseRoot(yamlText);
  const stepObj = getStepObj(rootObj, stepId);
  const stepType = String(stepObj.type || '');
  const fieldSpec = getFieldSpec(catalog, stepType, fieldKey);

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
  const stepObj = getStepObj(rootObj, stepId);
  const stepType = String(stepObj.type || '');
  const fieldSpec = getFieldSpec(catalog, stepType, fieldKey);

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
  const stepObj = getStepObj(rootObj, stepId);
  const stepType = String(stepObj.type || '');
  const fieldSpec = getFieldSpec(catalog, stepType, fieldKey);

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