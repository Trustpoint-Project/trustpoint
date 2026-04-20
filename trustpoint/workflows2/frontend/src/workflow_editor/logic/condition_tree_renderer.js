import {
  encodeConditionPath,
  getConditionKind,
} from '../document/condition_tree.js';
import { escapeHtml } from '../shared/dom.js';
import { renderInlineVariablePicker } from '../variables/inline_variable_picker.js';

function renderActionButton(actionAttribute, action, label, extraAttrs = '', tone = 'primary') {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-${tone}"
      ${actionAttribute}="${escapeHtml(action)}"${extraAttrs}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function getNodeDescription(kind) {
  switch (kind) {
    case 'exists':
      return 'True when the value exists.';
    case 'not':
      return 'Negates the nested condition.';
    case 'and':
      return 'All nested conditions must match.';
    case 'or':
      return 'At least one nested condition must match.';
    case 'compare':
    default:
      return 'Compare two values.';
  }
}

function renderKindOptions(currentKind) {
  return ['compare', 'exists', 'not', 'and', 'or']
    .map((kind) => {
      const selected = kind === currentKind ? ' selected' : '';
      return `<option value="${escapeHtml(kind)}"${selected}>${escapeHtml(kind)}</option>`;
    })
    .join('');
}

function canRemoveNode(path) {
  if (!Array.isArray(path) || !path.length) {
    return false;
  }

  return typeof path[path.length - 1] === 'number';
}

function renderNodeHeader({
  actionAttribute,
  caseIndex,
  kind,
  path,
  saveMode,
  stepId,
}) {
  const removable = canRemoveNode(path);
  const pathAttr = escapeHtml(encodeConditionPath(path));

  return `
    <div class="wf2-logic-tree-header">
      <div class="wf2-logic-tree-toolbar">
        <select class="form-select form-select-sm" data-condition-kind-select="true">
          ${renderKindOptions(kind)}
        </select>

        ${renderActionButton(
          actionAttribute,
          'set-logic-condition-kind',
          'Apply',
          ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${pathAttr}"`,
        )}

        ${
          removable
            ? renderActionButton(
                actionAttribute,
                'remove-logic-condition-node',
                'Remove',
                ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${pathAttr}"`,
                'danger',
              )
            : '<span></span>'
        }
      </div>

      <div class="wf2-logic-tree-help">
        ${escapeHtml(getNodeDescription(kind))}
      </div>
    </div>
  `;
}

function renderCompareNode({
  actionAttribute,
  availableVarNames,
  caseIndex,
  catalog,
  node,
  path,
  saveMode,
  stepId,
  triggerKey,
}) {
  const compare = node?.compare && typeof node.compare === 'object' ? node.compare : {};
  const compareOps = catalog?.dsl?.conditions?.compare_operators || ['==', '!=', '<', '<=', '>', '>='];
  const pathAttr = escapeHtml(encodeConditionPath(path));

  return `
    <div class="wf2-logic-tree-form-grid">
      <div class="wf2-logic-tree-field" data-inline-variable-scope="true">
        <label class="form-label form-label-sm mb-1">Left</label>
        <input
          type="text"
          class="form-control form-control-sm"
          data-inline-variable-target="value"
          data-logic-compare-left="true"
          value="${escapeHtml(compare.left ?? '')}"
        >
        ${renderInlineVariablePicker({
          actionAttribute,
          catalog,
          triggerKey,
          availableVarNames,
        })}
      </div>

      <div class="wf2-logic-tree-field">
        <label class="form-label form-label-sm mb-1">Compare operator</label>
        <select class="form-select form-select-sm" data-logic-compare-op="true">
          ${compareOps
            .map((op) => {
              const selected = String(compare.op || '==') === op ? ' selected' : '';
              return `<option value="${escapeHtml(op)}"${selected}>${escapeHtml(op)}</option>`;
            })
            .join('')}
        </select>
      </div>

      <div class="wf2-logic-tree-field wf2-logic-tree-field-full" data-inline-variable-scope="true">
        <label class="form-label form-label-sm mb-1">Right</label>
        <input
          type="text"
          class="form-control form-control-sm"
          data-inline-variable-target="value"
          data-logic-compare-right="true"
          value="${escapeHtml(compare.right ?? '')}"
        >
        ${renderInlineVariablePicker({
          actionAttribute,
          catalog,
          triggerKey,
          availableVarNames,
        })}
      </div>
    </div>

    ${
      saveMode === 'footer'
        ? ''
        : `
            <div class="wf2-logic-tree-actions">
              ${renderActionButton(
                actionAttribute,
                'save-logic-compare-node',
                'Save',
                ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${pathAttr}"`,
              )}
            </div>
          `
    }
  `;
}

function renderExistsNode({
  actionAttribute,
  availableVarNames,
  caseIndex,
  catalog,
  node,
  path,
  saveMode,
  stepId,
  triggerKey,
}) {
  const pathAttr = escapeHtml(encodeConditionPath(path));

  return `
    <div class="wf2-logic-tree-field" data-inline-variable-scope="true">
      <label class="form-label form-label-sm mb-1">Value</label>
      <input
        type="text"
        class="form-control form-control-sm"
        data-inline-variable-target="value"
        data-logic-exists-value="true"
        value="${escapeHtml(node?.exists ?? '')}"
      >
      ${renderInlineVariablePicker({
        actionAttribute,
        catalog,
        triggerKey,
        availableVarNames,
      })}
    </div>

    ${
      saveMode === 'footer'
        ? ''
        : `
            <div class="wf2-logic-tree-actions">
              ${renderActionButton(
                actionAttribute,
                'save-logic-exists-node',
                'Save',
                ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${pathAttr}"`,
              )}
            </div>
          `
    }
  `;
}

function renderChildrenBlock({
  actionAttribute,
  availableVarNames,
  caseIndex,
  catalog,
  children,
  path,
  saveMode,
  stepId,
  triggerKey,
}) {
  const pathAttr = escapeHtml(encodeConditionPath(path));

  return `
    <div class="wf2-logic-tree-children">
      ${(children || [])
        .map((childNode, index) =>
          renderLogicConditionTree({
            actionAttribute,
            availableVarNames,
            caseIndex,
            catalog,
            nested: true,
            node: childNode,
            path: [...path, index],
            saveMode,
            stepId,
            triggerKey,
          }),
        )
        .join('')}
    </div>

    <div class="wf2-logic-tree-actions">
      ${renderActionButton(
        actionAttribute,
        'add-logic-condition-child',
        'Add nested condition',
        ` data-step-id="${escapeHtml(stepId)}" data-case-index="${caseIndex}" data-condition-path="${pathAttr}"`,
      )}
    </div>
  `;
}

export function renderLogicConditionTree({
  actionAttribute = 'data-graph-overlay-action',
  availableVarNames = [],
  caseIndex,
  catalog,
  nested = false,
  node,
  path,
  stepId,
  triggerKey = null,
  saveMode = 'section',
}) {
  const kind = getConditionKind(node);
  const pathAttr = escapeHtml(encodeConditionPath(path));

  let bodyHtml = '';

  if (kind === 'compare') {
    bodyHtml = renderCompareNode({
      actionAttribute,
      availableVarNames,
      caseIndex,
      catalog,
      node,
      path,
      saveMode,
      stepId,
      triggerKey,
    });
  } else if (kind === 'exists') {
    bodyHtml = renderExistsNode({
      actionAttribute,
      availableVarNames,
      caseIndex,
      catalog,
      node,
      path,
      saveMode,
      stepId,
      triggerKey,
    });
  } else if (kind === 'not') {
    bodyHtml = `
      <div class="wf2-logic-tree-children">
        ${renderLogicConditionTree({
          actionAttribute,
          availableVarNames,
          caseIndex,
          catalog,
          nested: true,
          node: node?.not || { compare: { left: '${vars.value}', op: '==', right: '' } },
          path: [...path, 'not'],
          saveMode,
          stepId,
          triggerKey,
        })}
      </div>
    `;
  } else if (kind === 'and' || kind === 'or') {
    bodyHtml = renderChildrenBlock({
      actionAttribute,
      availableVarNames,
      caseIndex,
      catalog,
      children: Array.isArray(node?.[kind]) ? node[kind] : [],
      path,
      saveMode,
      stepId,
      triggerKey,
    });
  }

  return `
    <div
      class="wf2-logic-tree-node${nested ? ' wf2-logic-tree-node-nested' : ''}"
      data-condition-node-path="${pathAttr}"
      data-logic-node-scope="true"
    >
      ${renderNodeHeader({
        actionAttribute,
        caseIndex,
        kind,
        path,
        saveMode,
        stepId,
      })}

      ${bodyHtml}
    </div>
  `;
}
