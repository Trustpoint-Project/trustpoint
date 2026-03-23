import { escapeHtml } from '../core/dom.js';

const FALLBACK_OPERATORS = ['compare', 'exists', 'not', 'and', 'or'];
const FALLBACK_COMPARE_OPS = ['==', '!=', '<', '<=', '>', '>='];

function renderButton(action, label, extraAttrs = '', className = 'btn btn-sm btn-outline-primary') {
  return `
    <button
      type="button"
      class="${escapeHtml(className)}"
      data-graph-overlay-action="${escapeHtml(action)}"${extraAttrs}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function renderDangerButton(action, label, extraAttrs = '') {
  return renderButton(action, label, extraAttrs, 'btn btn-sm btn-outline-danger');
}

function encodePath(path = []) {
  return path.map((part) => String(part)).join('.');
}

function getConditionOperator(condition) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
    return null;
  }

  const keys = Object.keys(condition);
  if (keys.length !== 1) {
    return null;
  }

  return keys[0];
}

function getConditionValue(condition, operator) {
  if (!condition || typeof condition !== 'object' || Array.isArray(condition)) {
    return null;
  }
  return condition[operator];
}

function getOperatorOptions(catalog) {
  const ops = (catalog?.dsl?.conditions?.operators || [])
    .map((item) => item?.key)
    .filter(Boolean);

  return ops.length ? ops : FALLBACK_OPERATORS;
}

function getCompareOperators(catalog) {
  const ops = catalog?.dsl?.conditions?.compare_operators || [];
  return ops.length ? ops : FALLBACK_COMPARE_OPS;
}

function renderOperatorSelector(catalog, selectedOperator) {
  return `
    <select
      class="form-select form-select-sm wf2-cond-operator-select"
      data-logic-condition-operator="true"
    >
      ${getOperatorOptions(catalog)
        .map((operator) => {
          const selected = operator === selectedOperator ? ' selected' : '';
          return `<option value="${escapeHtml(operator)}"${selected}>${escapeHtml(operator)}</option>`;
        })
        .join('')}
    </select>
  `;
}

function renderNodeHeader({
  stepId,
  caseIndex,
  path,
  catalog,
  selectedOperator,
  canRemove,
}) {
  return `
    <div class="wf2-cond-header">
      <div class="wf2-cond-header-main">
        <label class="form-label form-label-sm mb-1">Operator</label>
        <div class="wf2-cond-header-row">
          <div class="wf2-cond-header-select">
            ${renderOperatorSelector(catalog, selectedOperator)}
          </div>

          <div class="wf2-cond-header-actions">
            ${renderButton(
              'set-logic-condition-operator',
              'Apply',
              ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${escapeHtml(encodePath(path))}"`,
            )}

            ${
              canRemove
                ? renderDangerButton(
                    'remove-logic-condition-node',
                    'Remove',
                    ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${escapeHtml(encodePath(path))}"`,
                  )
                : ''
            }
          </div>
        </div>
      </div>
    </div>
  `;
}

function renderCompareEditor({
  stepId,
  caseIndex,
  path,
  compare,
  catalog,
}) {
  const leftValue = compare?.left ?? '';
  const rightValue = compare?.right ?? '';
  const opValue = compare?.op ?? '==';

  return `
    <div class="mb-2">
      <label class="form-label form-label-sm mb-1">Left</label>
      <input
        type="text"
        class="form-control form-control-sm"
        data-logic-condition-left="true"
        value="${escapeHtml(leftValue)}"
      >
    </div>

    <div class="mb-2">
      <label class="form-label form-label-sm mb-1">Compare operator</label>
      <select class="form-select form-select-sm" data-logic-condition-compare-op="true">
        ${getCompareOperators(catalog)
          .map((op) => {
            const selected = op === opValue ? ' selected' : '';
            return `<option value="${escapeHtml(op)}"${selected}>${escapeHtml(op)}</option>`;
          })
          .join('')}
      </select>
    </div>

    <div class="mb-2">
      <label class="form-label form-label-sm mb-1">Right</label>
      <input
        type="text"
        class="form-control form-control-sm"
        data-logic-condition-right="true"
        value="${escapeHtml(rightValue)}"
      >
    </div>

    <div class="d-flex justify-content-start">
      ${renderButton(
        'save-logic-condition-compare',
        'Save',
        ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${escapeHtml(encodePath(path))}"`,
      )}
    </div>
  `;
}

function renderExistsEditor({
  stepId,
  caseIndex,
  path,
  value,
}) {
  return `
    <div class="mb-2">
      <label class="form-label form-label-sm mb-1">Value</label>
      <input
        type="text"
        class="form-control form-control-sm"
        data-logic-condition-value="true"
        value="${escapeHtml(value ?? '')}"
      >
    </div>

    <div class="d-flex justify-content-start">
      ${renderButton(
        'save-logic-condition-exists',
        'Save',
        ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${escapeHtml(encodePath(path))}"`,
      )}
    </div>
  `;
}

function renderConditionNode({
  stepId,
  caseIndex,
  condition,
  path,
  catalog,
  canRemove = false,
  depth = 0,
}) {
  const rawOperator = getConditionOperator(condition);
  const supportedOperators = new Set(getOperatorOptions(catalog));
  const selectedOperator = supportedOperators.has(rawOperator) ? rawOperator : 'compare';

  let noticeHtml = '';
  if (!rawOperator || !supportedOperators.has(rawOperator)) {
    noticeHtml = `
      <div class="small text-muted mb-2">
        Unsupported or invalid condition shape. Choose an operator and save to normalize it.
      </div>
    `;
  }

  const value = rawOperator === selectedOperator ? getConditionValue(condition, selectedOperator) : null;

  let bodyHtml = '';

  if (selectedOperator === 'compare') {
    bodyHtml = renderCompareEditor({
      stepId,
      caseIndex,
      path,
      compare: value && typeof value === 'object' && !Array.isArray(value) ? value : {},
      catalog,
    });
  } else if (selectedOperator === 'exists') {
    bodyHtml = renderExistsEditor({
      stepId,
      caseIndex,
      path,
      value,
    });
  } else if (selectedOperator === 'not') {
    const childCondition =
      value && typeof value === 'object' && !Array.isArray(value)
        ? value
        : { compare: { left: '${vars.value}', op: '==', right: '' } };

    bodyHtml = `
      <div class="small text-muted mb-2">
        Negates exactly one nested condition.
      </div>

      ${renderConditionNode({
        stepId,
        caseIndex,
        condition: childCondition,
        path: [...path, 'not'],
        catalog,
        canRemove: false,
        depth: depth + 1,
      })}
    `;
  } else if (selectedOperator === 'and' || selectedOperator === 'or') {
    const children = Array.isArray(value) ? value : [];

    bodyHtml = `
      <div class="small text-muted mb-2">
        ${selectedOperator === 'and' ? 'All nested conditions must match.' : 'At least one nested condition must match.'}
      </div>

      ${
        children.length
          ? children
              .map((child, index) =>
                renderConditionNode({
                  stepId,
                  caseIndex,
                  condition: child,
                  path: [...path, selectedOperator, index],
                  catalog,
                  canRemove: true,
                  depth: depth + 1,
                }),
              )
              .join('')
          : '<div class="small text-muted mb-2">No nested conditions yet.</div>'
      }

      <div class="d-flex justify-content-start mt-2">
        ${renderButton(
          'add-logic-condition-child',
          'Add nested condition',
          ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${escapeHtml(encodePath(path))}"`,
        )}
      </div>
    `;
  }

  return `
    <div
      class="wf2-cond-node ${depth > 0 ? 'wf2-cond-node-nested' : ''}"
      data-logic-condition-node="true"
      data-condition-path="${escapeHtml(encodePath(path))}"
    >
      ${renderNodeHeader({
        stepId,
        caseIndex,
        path,
        catalog,
        selectedOperator,
        canRemove,
      })}

      ${noticeHtml}
      ${bodyHtml}
    </div>
  `;
}

export function renderLogicConditionEditorTree({
  stepId,
  caseIndex,
  condition,
  catalog,
}) {
  return renderConditionNode({
    stepId,
    caseIndex,
    condition,
    path: [],
    catalog,
    canRemove: false,
    depth: 0,
  });
}