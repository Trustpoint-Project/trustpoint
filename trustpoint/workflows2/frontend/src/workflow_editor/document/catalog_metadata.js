import { findStepSpec, extractStepOutcomes as extractCatalogStepOutcomes } from './catalog_lookup.js';
import { deepClone } from './yaml_document.js';

export { findStepSpec };

export function getCommonStepFields(catalog, { excludeKeys = [] } = {}) {
  const excluded = new Set(excludeKeys);
  return (catalog?.meta?.common_step_fields || []).filter((field) => !excluded.has(field.key));
}

export function getStepFieldSpecs(catalog, stepType, { excludeKeys = [] } = {}) {
  const stepSpec = findStepSpec(catalog, stepType);
  const excluded = new Set(excludeKeys);
  const commonFields = getCommonStepFields(catalog, { excludeKeys });
  const stepFields = (stepSpec?.fields || []).filter((field) => !excluded.has(field.key));
  return [...commonFields, ...stepFields];
}

export function getFieldSpec(catalog, stepType, fieldKey, { excludeKeys = [] } = {}) {
  return (
    getStepFieldSpecs(catalog, stepType, { excludeKeys }).find((field) => field.key === fieldKey) ||
    null
  );
}

export function getFieldSeed(fieldSpec) {
  if (fieldSpec && Object.prototype.hasOwnProperty.call(fieldSpec, 'scaffold')) {
    return deepClone(fieldSpec.scaffold);
  }

  if (fieldSpec && Object.prototype.hasOwnProperty.call(fieldSpec, 'default')) {
    return deepClone(fieldSpec.default);
  }

  return null;
}

export function isStructuredField(fieldSpec) {
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

export function fallbackFieldValue(fieldSpec) {
  const seed = getFieldSeed(fieldSpec);
  if (seed !== null && seed !== undefined) {
    return seed;
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

export function normalizeStepBase(stepType) {
  const base = String(stepType || 'step')
    .trim()
    .replace(/[^a-zA-Z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '');

  return base || 'step';
}

export function makeUniqueKey(existingKeys, baseKey) {
  if (!existingKeys.includes(baseKey)) {
    return baseKey;
  }

  let index = 2;
  while (existingKeys.includes(`${baseKey}_${index}`)) {
    index += 1;
  }

  return `${baseKey}_${index}`;
}

export function makeUniqueStepId(existingIds, stepType) {
  return makeUniqueKey(existingIds, normalizeStepBase(stepType));
}

export function extractStepOutcomes(stepObj) {
  return extractCatalogStepOutcomes(stepObj, { rejectArrays: true });
}

export function isOutcomeProducingStep(stepObj) {
  return extractStepOutcomes(stepObj).length > 0;
}
