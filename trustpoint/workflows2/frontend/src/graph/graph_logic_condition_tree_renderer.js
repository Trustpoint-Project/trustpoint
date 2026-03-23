import { escapeHtml } from '../core/dom.js';

function encodePath(path) {
  return escapeHtml(JSON.stringify(Array.isArray(path) ? path : []));
}

function getNodeKind(node) {
  if (!node || typeof node !== 'object' || Array.isArray(node)) {
    return 'compare';
  }

  if (Object.prototype.hasOwnProperty.call(node, 'compare')) {
    return 'compare';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'exists')) {
    return 'exists';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'not')) {
    return 'not';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'and')) {
    return 'and';
  }
  if (Object.prototype.hasOwnProperty.call(node, 'or')) {
    return 'or';
  }

  return 'compare';
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
  const options = ['compare', 'exists', 'not', 'and', 'or'];

  return options
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
  stepId,
  caseIndex,
  path,
  kind,
}) {
  const removable = canRemoveNode(path);
  const pathAttr = encodePath(path);

  return `
    <div class="wf2-logic-tree-header">
      <div class="wf2-logic-tree-toolbar">
        <select class="form-select form-select-sm" data-condition-kind-select="true">
          ${renderKindOptions(kind)}
        </select>

        <button
          type="button"
          class="btn btn-sm btn-outline-primary"
          data-graph-overlay-action="set-logic-condition-kind"
          data-step-id="${escapeHtml(stepId)}"
          data-case-index="${caseIndex}"
          data-condition-path="${pathAttr}"
        >
          Apply
        </button>

        ${
          removable
            ? `
              <button
                type="button"
                class="btn btn-sm btn-outline-danger"
                data-graph-overlay-action="remove-logic-condition-node"
                data-step-id="${escapeHtml(stepId)}"
                data-case-index="${caseIndex}"
                data-condition-path="${pathAttr}"
              >
                Remove
              </button>
            `
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
  stepId,
  caseIndex,
  path,
  node,
  catalog,
}) {
  const compare = node?.compare && typeof node.compare === 'object' ? node.compare : {};
  const compareOps = catalog?.dsl?.conditions?.compare_operators || ['==', '!=', '<', '<=', '>', '>='];
  const pathAttr = encodePath(path);

  return `
    <div class="wf2-logic-tree-form-grid">
      <div class="wf2-logic-tree-field">
        <label class="form-label form-label-sm mb-1">Left</label>
        <input
          type="text"
          class="form-control form-control-sm"
          data-logic-compare-left="true"
          value="${escapeHtml(compare.left ?? '')}"
        >
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

      <div class="wf2-logic-tree-field wf2-logic-tree-field-full">
        <label class="form-label form-label-sm mb-1">Right</label>
        <input
          type="text"
          class="form-control form-control-sm"
          data-logic-compare-right="true"
          value="${escapeHtml(compare.right ?? '')}"
        >
      </div>
    </div>

    <div class="wf2-logic-tree-actions">
      <button
        type="button"
        class="btn btn-sm btn-outline-primary"
        data-graph-overlay-action="save-logic-compare-node"
        data-step-id="${escapeHtml(stepId)}"
        data-case-index="${caseIndex}"
        data-condition-path="${pathAttr}"
      >
        Save
      </button>
    </div>
  `;
}

function renderExistsNode({
  stepId,
  caseIndex,
  path,
  node,
}) {
  const pathAttr = encodePath(path);

  return `
    <div class="wf2-logic-tree-field">
      <label class="form-label form-label-sm mb-1">Value</label>
      <input
        type="text"
        class="form-control form-control-sm"
        data-logic-exists-value="true"
        value="${escapeHtml(node?.exists ?? '')}"
      >
    </div>

    <div class="wf2-logic-tree-actions">
      <button
        type="button"
        class="btn btn-sm btn-outline-primary"
        data-graph-overlay-action="save-logic-exists-node"
        data-step-id="${escapeHtml(stepId)}"
        data-case-index="${caseIndex}"
        data-condition-path="${pathAttr}"
      >
        Save
      </button>
    </div>
  `;
}

function renderChildrenBlock({
  stepId,
  caseIndex,
  path,
  children,
  catalog,
}) {
  const pathAttr = encodePath(path);

  return `
    <div class="wf2-logic-tree-children">
      ${(children || [])
        .map((childNode, index) =>
          renderLogicConditionTree({
            stepId,
            caseIndex,
            path: [...path, index],
            node: childNode,
            catalog,
            nested: true,
          }),
        )
        .join('')}
    </div>

    <div class="wf2-logic-tree-actions">
      <button
        type="button"
        class="btn btn-sm btn-outline-primary"
        data-graph-overlay-action="add-logic-condition-child"
        data-step-id="${escapeHtml(stepId)}"
        data-case-index="${caseIndex}"
        data-condition-path="${pathAttr}"
      >
        Add nested condition
      </button>
    </div>
  `;
}

export function renderLogicConditionTree({
  stepId,
  caseIndex,
  path,
  node,
  catalog,
  nested = false,
}) {
  const kind = getNodeKind(node);
  const pathAttr = encodePath(path);

  let bodyHtml = '';

  if (kind === 'compare') {
    bodyHtml = renderCompareNode({
      stepId,
      caseIndex,
      path,
      node,
      catalog,
    });
  } else if (kind === 'exists') {
    bodyHtml = renderExistsNode({
      stepId,
      caseIndex,
      path,
      node,
    });
  } else if (kind === 'not') {
    bodyHtml = `
      <div class="wf2-logic-tree-children">
        ${renderLogicConditionTree({
          stepId,
          caseIndex,
          path: [...path, 'not'],
          node: node?.not || { compare: { left: '${vars.value}', op: '==', right: '' } },
          catalog,
          nested: true,
        })}
      </div>
    `;
  } else if (kind === 'and' || kind === 'or') {
    bodyHtml = renderChildrenBlock({
      stepId,
      caseIndex,
      path,
      children: Array.isArray(node?.[kind]) ? node[kind] : [],
      catalog,
    });
  }

  return `
    <div
      class="wf2-logic-tree-node${nested ? ' wf2-logic-tree-node-nested' : ''}"
      data-condition-node-path="${pathAttr}"
    >
      ${renderNodeHeader({
        stepId,
        caseIndex,
        path,
        kind,
      })}

      ${bodyHtml}
    </div>
  `;
}