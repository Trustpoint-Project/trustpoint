import { escapeHtml } from '../shared/dom.js';
import {
  encodePath,
  getCompareOps,
  getConditionOperator,
  getOperatorDescription,
  renderButton,
} from './guide_apply_shared.js';
import {
  renderAddChildControls,
  renderNodeOperatorRow,
} from './guide_apply_node_controls.js';

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

export function renderConditionNode({
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
    return renderExistsNode({ catalog, ruleIndex, path, node, isRoot, allowRemove, extraClass });
  }

  if (operatorName === 'compare') {
    return renderCompareNode({ catalog, ruleIndex, path, node, isRoot, allowRemove, extraClass });
  }

  if (operatorName === 'not') {
    return renderNotNode({ catalog, ruleIndex, path, node, isRoot, allowRemove, extraClass });
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

  return renderUnsupportedNode({ catalog, ruleIndex, path, isRoot, allowRemove, extraClass });
}
