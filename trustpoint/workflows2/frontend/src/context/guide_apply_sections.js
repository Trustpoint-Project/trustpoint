import { parseDocument } from 'yaml';

import { escapeHtml } from '../core/dom.js';
import {
  buildVariableSuggestions,
  renderVariableButtons,
} from './guide_ui_helpers.js';
import { renderConditionDsl } from './guide_dsl_sections.js';

function renderButton(action, label, extraAttrs = '') {
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

function renderDangerButton(action, label, extraAttrs = '') {
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

function parseApplyItems(yamlText) {
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

function getConditionOperator(node) {
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

function encodePath(path) {
  return escapeHtml(JSON.stringify(path || []));
}

function getOperatorOptions(catalog) {
  const ops = catalog?.dsl?.conditions?.operators || [];
  const keys = ops
    .map((item) => item?.key)
    .filter(Boolean);

  return keys.length ? keys : ['exists', 'compare', 'not', 'and', 'or'];
}

function getCompareOps(catalog) {
  const ops = catalog?.dsl?.conditions?.compare_operators || [];
  return ops.length ? ops : ['==', '!=', '<', '<=', '>', '>='];
}

function getOperatorDescription(operatorName) {
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

function renderNodeOperatorRow({
  catalog,
  currentOperator,
  ruleIndex,
  path,
  isRoot,
  allowRemove,
}) {
  const encodedPath = encodePath(path);
  const options = getOperatorOptions(catalog);

  return `
    <div class="wf2-cond-header-row">
      <div class="wf2-cond-header-main">
        <label class="form-label form-label-sm mb-1">Operator</label>
        <select class="form-select form-select-sm wf2-cond-operator-select" data-apply-node-operator-input="true">
          ${options
            .map((operatorName) => {
              const selected = operatorName === currentOperator ? ' selected' : '';
              return `<option value="${escapeHtml(operatorName)}"${selected}>${escapeHtml(operatorName)}</option>`;
            })
            .join('')}
        </select>
      </div>

      <div class="wf2-cond-header-actions">
        ${renderButton(
          'set-apply-node-operator',
          'Apply',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}

        ${
          allowRemove
            ? (
                isRoot
                  ? renderDangerButton(
                      'remove-apply-rule',
                      'Remove rule',
                      ` data-apply-rule-index="${ruleIndex}"`,
                    )
                  : renderDangerButton(
                      'remove-apply-child',
                      'Remove',
                      ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
                    )
              )
            : ''
        }
      </div>
    </div>
  `;
}

function renderAddChildControls(ruleIndex, path) {
  const encodedPath = encodePath(path);

  return `
    <div class="wf2-inline-save-row" data-apply-child-controls="true">
      <div class="wf2-inline-save-input">
        <label class="form-label form-label-sm mb-1">Add nested condition</label>
        <select class="form-select form-select-sm" data-apply-child-operator-input="true">
          <option value="compare">compare</option>
          <option value="exists">exists</option>
          <option value="not">not</option>
          <option value="and">and</option>
          <option value="or">or</option>
        </select>
      </div>

      <div class="wf2-inline-save-action">
        <label class="form-label form-label-sm mb-1 d-block">&nbsp;</label>
        ${renderButton(
          'add-apply-child',
          'Add',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}
      </div>
    </div>
  `;
}

function renderExistsNode({
  catalog,
  ruleIndex,
  path,
  node,
  isRoot,
  allowRemove,
  extraClass = '',
}) {
  const encodedPath = encodePath(path);

  return `
    <div class="wf2-cond-node${extraClass}" data-apply-scope="true">
      <div class="wf2-cond-header">
        ${renderNodeOperatorRow({
          catalog,
          currentOperator: 'exists',
          ruleIndex,
          path,
          isRoot,
          allowRemove,
        })}
        <div class="small text-muted mt-1">${escapeHtml(getOperatorDescription('exists'))}</div>
      </div>

      <div class="wf2-inline-save-row">
        <div class="wf2-inline-save-input">
          <label class="form-label form-label-sm mb-1">Value</label>
          <input
            type="text"
            class="form-control form-control-sm"
            data-apply-exists-input="true"
            value="${escapeHtml(node?.exists ?? '')}"
          >
        </div>

        <div class="wf2-inline-save-action">
          <label class="form-label form-label-sm mb-1 d-block">&nbsp;</label>
          ${renderButton(
            'save-apply-exists',
            'Save',
            ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
          )}
        </div>
      </div>
    </div>
  `;
}

function renderCompareNode({
  catalog,
  ruleIndex,
  path,
  node,
  isRoot,
  allowRemove,
  extraClass = '',
}) {
  const encodedPath = encodePath(path);
  const compare = node?.compare || {};
  const compareOps = getCompareOps(catalog);

  return `
    <div class="wf2-cond-node${extraClass}" data-apply-scope="true">
      <div class="wf2-cond-header">
        ${renderNodeOperatorRow({
          catalog,
          currentOperator: 'compare',
          ruleIndex,
          path,
          isRoot,
          allowRemove,
        })}
        <div class="small text-muted mt-1">${escapeHtml(getOperatorDescription('compare'))}</div>
      </div>

      <div class="mb-2">
        <label class="form-label form-label-sm mb-1">Left</label>
        <input
          type="text"
          class="form-control form-control-sm"
          data-apply-compare-left-input="true"
          value="${escapeHtml(compare.left ?? '')}"
        >
      </div>

      <div class="mb-2">
        <label class="form-label form-label-sm mb-1">Compare operator</label>
        <select class="form-select form-select-sm" data-apply-compare-op-input="true">
          ${compareOps
            .map((op) => {
              const selected = String(compare.op ?? '==') === op ? ' selected' : '';
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
          data-apply-compare-right-input="true"
          value="${escapeHtml(compare.right ?? '')}"
        >
      </div>

      ${renderButton(
        'save-apply-compare',
        'Save',
        ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
      )}
    </div>
  `;
}

function renderNotNode({
  catalog,
  ruleIndex,
  path,
  node,
  isRoot,
  allowRemove,
  extraClass = '',
}) {
  const child = node?.not || null;

  return `
    <div class="wf2-cond-node${extraClass}" data-apply-scope="true">
      <div class="wf2-cond-header">
        ${renderNodeOperatorRow({
          catalog,
          currentOperator: 'not',
          ruleIndex,
          path,
          isRoot,
          allowRemove,
        })}
        <div class="small text-muted mt-1">${escapeHtml(getOperatorDescription('not'))}</div>
      </div>

      ${
        child
          ? `
            <div class="wf2-cond-node-nested">
              ${renderConditionNode({
                catalog,
                ruleIndex,
                path: [...path, 0],
                node: child,
                isRoot: false,
                allowRemove: false,
              })}
            </div>
          `
          : `
            <div class="wf2-cond-node-nested">
              ${renderAddChildControls(ruleIndex, path)}
            </div>
          `
      }
    </div>
  `;
}

function renderGroupNode({
  catalog,
  operatorName,
  ruleIndex,
  path,
  node,
  isRoot,
  allowRemove,
  extraClass = '',
}) {
  const children = Array.isArray(node?.[operatorName]) ? node[operatorName] : [];

  return `
    <div class="wf2-cond-node${extraClass}" data-apply-scope="true">
      <div class="wf2-cond-header">
        ${renderNodeOperatorRow({
          catalog,
          currentOperator: operatorName,
          ruleIndex,
          path,
          isRoot,
          allowRemove,
        })}
        <div class="small text-muted mt-1">${escapeHtml(getOperatorDescription(operatorName))}</div>
      </div>

      <div class="wf2-cond-node-nested">
        ${
          children.length
            ? children
                .map((child, index) =>
                  renderConditionNode({
                    catalog,
                    ruleIndex,
                    path: [...path, index],
                    node: child,
                    isRoot: false,
                    allowRemove: true,
                  }),
                )
                .join('')
            : '<div class="small text-muted mb-2">No nested conditions yet.</div>'
        }

        ${renderAddChildControls(ruleIndex, path)}
      </div>
    </div>
  `;
}

function renderUnsupportedNode({
  catalog,
  ruleIndex,
  path,
  isRoot,
  allowRemove,
  extraClass = '',
}) {
  const encodedPath = encodePath(path);

  return `
    <div class="wf2-cond-node${extraClass}" data-apply-scope="true">
      <div class="wf2-cond-header">
        ${renderNodeOperatorRow({
          catalog,
          currentOperator: 'compare',
          ruleIndex,
          path,
          isRoot,
          allowRemove,
        })}
      </div>

      <div class="small text-muted">
        This apply condition shape is not editable in the structured UI yet. Edit it in YAML or switch its operator here.
      </div>

      <div class="mt-2">
        ${renderButton(
          'set-apply-node-operator',
          'Reset to compare',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}
      </div>
    </div>
  `;
}

function renderConditionNode({
  catalog,
  ruleIndex,
  path,
  node,
  isRoot,
  allowRemove,
  extraClass = '',
}) {
  const operatorName = getConditionOperator(node);

  if (operatorName === 'exists') {
    return renderExistsNode({
      catalog,
      ruleIndex,
      path,
      node,
      isRoot,
      allowRemove,
      extraClass,
    });
  }

  if (operatorName === 'compare') {
    return renderCompareNode({
      catalog,
      ruleIndex,
      path,
      node,
      isRoot,
      allowRemove,
      extraClass,
    });
  }

  if (operatorName === 'not') {
    return renderNotNode({
      catalog,
      ruleIndex,
      path,
      node,
      isRoot,
      allowRemove,
      extraClass,
    });
  }

  if (operatorName === 'and' || operatorName === 'or') {
    return renderGroupNode({
      catalog,
      operatorName,
      ruleIndex,
      path,
      node,
      isRoot,
      allowRemove,
      extraClass,
    });
  }

  return renderUnsupportedNode({
    catalog,
    ruleIndex,
    path,
    isRoot,
    allowRemove,
    extraClass,
  });
}

function renderApplyRule(rule, ruleIndex, isCurrent, catalog) {
  return `
    <div class="mb-3">
      <div class="fw-semibold mb-2">
        Apply rule ${ruleIndex + 1}${isCurrent ? ' · current' : ''}
      </div>

      ${renderConditionNode({
        catalog,
        ruleIndex,
        path: [],
        node: rule,
        isRoot: true,
        allowRemove: true,
        extraClass: isCurrent ? ' border-primary' : '',
      })}
    </div>
  `;
}

export function renderApplyGuide(context, catalog, yamlText = '') {
  const applyItems = parseApplyItems(yamlText);
  const currentRuleIndex =
    Array.isArray(context?.path) && typeof context.path[1] === 'number'
      ? context.path[1]
      : null;

  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Apply rules</div>
      <div class="text-muted">
        These conditions are evaluated before the workflow starts.
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-2">Add apply rule</div>
      <div class="d-flex flex-wrap gap-2">
        ${renderButton('add-apply-rule', 'Add compare', ' data-apply-operator="compare"')}
        ${renderButton('add-apply-rule', 'Add exists', ' data-apply-operator="exists"')}
        ${renderButton('add-apply-rule', 'Add not', ' data-apply-operator="not"')}
        ${renderButton('add-apply-rule', 'Add and', ' data-apply-operator="and"')}
        ${renderButton('add-apply-rule', 'Add or', ' data-apply-operator="or"')}
      </div>
    </div>

    <div class="mb-3">
      ${
        applyItems.length
          ? applyItems
              .map((rule, index) => renderApplyRule(rule, index, currentRuleIndex === index, catalog))
              .join('')
          : '<div class="small text-muted">No apply rules yet.</div>'
      }
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Insert event variable</div>
      ${renderVariableButtons(eventButtons)}
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Insert workflow var</div>
      ${renderVariableButtons(varsButtons)}
    </div>

    ${renderConditionDsl(catalog)}
  `;
}