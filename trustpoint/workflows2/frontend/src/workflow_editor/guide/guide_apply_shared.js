import { parseDocument } from 'yaml';

import { escapeHtml } from '../shared/dom.js';

export function renderButton(action, label, extraAttrs = '') {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-primary"
      data-wf2-action="${escapeHtml(action)}"${extraAttrs}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

export function renderDangerButton(action, label, extraAttrs = '') {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-danger"
      data-wf2-action="${escapeHtml(action)}"${extraAttrs}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

export function parseApplyItems(yamlText) {
  try {
    const doc = parseDocument(yamlText || '', { prettyErrors: true });
    if (doc.errors.length) {
      return [];
    }

    const rootObj = doc.toJS() || {};
    return Array.isArray(rootObj.apply) ? rootObj.apply : [];
  } catch {
    return [];
  }
}

export function getConditionOperator(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return null;
  }

  for (const key of ['exists', 'compare', 'not', 'and', 'or']) {
    if (Object.prototype.hasOwnProperty.call(node, key)) {
      return key;
    }
  }

  return null;
}

export function encodePath(path) {
  return escapeHtml(JSON.stringify(path || []));
}

export function getOperatorOptions(catalog) {
  const ops = catalog?.dsl?.conditions?.operators || [];
  const keys = ops
    .map((item) => item?.key)
    .filter(Boolean);

  return keys.length ? keys : ['exists', 'compare', 'not', 'and', 'or'];
}

export function getCompareOps(catalog) {
  const ops = catalog?.dsl?.conditions?.compare_operators || [];
  return ops.length ? ops : ['==', '!=', '<', '<=', '>', '>='];
}

export function getOperatorDescription(operatorName) {
  if (operatorName === 'and') {
    return 'All nested conditions must match.';
  }

  if (operatorName === 'or') {
    return 'Any nested condition may match.';
  }

  if (operatorName === 'not') {
    return 'Negates the nested condition.';
  }

  if (operatorName === 'exists') {
    return 'Checks that a value is present.';
  }

  if (operatorName === 'compare') {
    return 'Compares two values.';
  }

  return '';
}
