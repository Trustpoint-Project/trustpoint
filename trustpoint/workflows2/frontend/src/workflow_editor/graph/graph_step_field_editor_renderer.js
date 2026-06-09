import { escapeHtml } from '../shared/dom.js';
import { renderStructuredStepFields } from './graph_step_structured_fields_renderer.js';
import { fitPanelToViewport, placePanelNearNode } from './graph_overlay_position.js';
import { renderInlineVariablePicker } from '../variables/inline_variable_picker.js';
import { getStepFieldSuggestions } from '../document/step_field_suggestions.js';
import { APPROVAL_OUTCOME_PRESETS } from '../document/approval_outcome_presets.js';
import {
  getCompareOps,
  getConditionOperator,
  getOperatorDescription,
  getOperatorOptions,
} from '../guide/guide_apply_shared.js';

function hasOwn(obj, key) {
  return !!obj && Object.prototype.hasOwnProperty.call(obj, key);
}

function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

function findTriggerSpec(catalog, triggerKey) {
  return (catalog?.events || []).find((eventSpec) => eventSpec.key === triggerKey) || null;
}

function getFieldSpecs(catalog, stepType) {
  const commonFields = (catalog?.meta?.common_step_fields || []).filter(
    (field) => field.key !== 'type' && field.key !== 'title',
  );
  const stepSpec = findStepSpec(catalog, stepType);
  return [...commonFields, ...(stepSpec?.fields || [])];
}

function isStructuredFieldKind(fieldKind) {
  return [
    'mapping',
    'list',
    'condition',
    'condition_list',
    'capture_mapping',
    'vars_mapping',
    'compute_mapping',
  ].includes(fieldKind);
}

function isSpecialManagedField(stepType, fieldKey) {
  if (stepType === 'logic') {
    return fieldKey === 'cases' || fieldKey === 'default';
  }

  if (stepType === 'webhook') {
    return fieldKey === 'capture';
  }

  if (stepType === 'compute') {
    return fieldKey === 'set';
  }

  if (stepType === 'set') {
    return fieldKey === 'vars';
  }

  return false;
}

function formatFieldValue(value, fieldKind) {
  if (value === undefined || value === null) {
    return '';
  }

  if (isStructuredFieldKind(fieldKind)) {
    if (typeof value === 'string') {
      return value;
    }
    try {
      return JSON.stringify(value, null, 2);
    } catch {
      return String(value);
    }
  }

  return String(value);
}

function supportsInlineVariablePicker(fieldKind) {
  return ['string', 'template', 'text', 'mapping', 'list'].includes(fieldKind);
}

function renderCloseButton() {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-secondary"
      data-graph-overlay-action="close-editor"
      aria-label="Close"
      title="Close"
    >
      ×
    </button>
  `;
}

function renderMetaPill(label, value) {
  return `
    <span class="wf2-graph-meta-pill">
      <span>${escapeHtml(label)}</span>
      <strong>${escapeHtml(value)}</strong>
    </span>
  `;
}

function renderSection(title, body, description = '') {
  return `
    <section class="wf2-graph-editor-section">
      <div class="wf2-graph-editor-section-title">${escapeHtml(title)}</div>
      ${description ? `<div class="wf2-graph-editor-section-description">${escapeHtml(description)}</div>` : ''}
      ${body}
    </section>
  `;
}

function renderVariableReferenceChips(varNames, { prefix = 'vars.', emptyLabel = 'None' } = {}) {
  if (!Array.isArray(varNames) || !varNames.length) {
    return `<div class="small text-muted">${escapeHtml(emptyLabel)}</div>`;
  }

  return `
    <div class="wf2-runtime-chip-row">
      ${varNames
        .map(
          (name) =>
            `<span class="wf2-chip"><strong>${escapeHtml(`${prefix}${name}`)}</strong></span>`,
        )
        .join('')}
    </div>
  `;
}

function renderEventVariableReferences(catalog, triggerKey) {
  const triggerSpec = triggerKey ? findTriggerSpec(catalog, triggerKey) : null;
  const contextVars = Array.isArray(triggerSpec?.context_vars) ? triggerSpec.context_vars : [];

  if (!contextVars.length) {
    return '<div class="small text-muted">No trigger variables documented for the current event.</div>';
  }

  return `
    <div class="wf2-runtime-chip-row">
      ${contextVars
        .map((item) => {
          const label = item?.template || `\${${item?.path || ''}}`;
          const title = item?.title || item?.path || label;
          return `<span class="wf2-chip" title="${escapeHtml(title)}"><strong>${escapeHtml(label)}</strong></span>`;
        })
        .join('')}
    </div>
  `;
}

function renderStepSummarySection(catalog, graph, node) {
  const reachability = node.is_unreachable
    ? 'This step is currently unreachable from workflow.start.'
    : 'This step is reachable from workflow.start.';

  return renderSection(
    'Step summary',
    `
      <div class="small text-muted mb-3">${escapeHtml(reachability)}</div>

      <div class="mb-3">
        <div class="fw-semibold mb-1">Trigger variables</div>
        ${renderEventVariableReferences(catalog, graph?.trigger_key)}
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-1">Workflow vars available here</div>
        ${renderVariableReferenceChips(node.available_var_names, {
          emptyLabel: node.is_unreachable
            ? 'Unavailable while the step is unreachable.'
            : 'No workflow vars are guaranteed here yet.',
        })}
      </div>

      <div>
        <div class="fw-semibold mb-1">Workflow vars written by this step</div>
        ${renderVariableReferenceChips(node.produced_var_names, {
          emptyLabel: 'This step does not define workflow vars.',
        })}
      </div>
    `,
    'Compact runtime reference for the current step.',
  );
}

function renderFieldInput(field, currentValue, { targetAttr = '' } = {}) {
  const value = formatFieldValue(currentValue, field.field_kind);

  if (Array.isArray(field.enum) && field.enum.length) {
    return `
      <select class="form-select form-select-sm" data-step-field-input="true">
        ${field.enum
          .map((item) => {
            const selected = String(currentValue ?? '') === String(item) ? ' selected' : '';
            return `<option value="${escapeHtml(item)}"${selected}>${escapeHtml(item)}</option>`;
          })
          .join('')}
      </select>
    `;
  }

  if (field.field_kind === 'text' || isStructuredFieldKind(field.field_kind)) {
    return `
      <textarea
        class="form-control form-control-sm font-monospace"
        rows="${isStructuredFieldKind(field.field_kind) ? '5' : '4'}"
        spellcheck="false"
        ${targetAttr}
        data-step-field-input="true"
      >${escapeHtml(value)}</textarea>
    `;
  }

  if (field.field_kind === 'int') {
    return `
      <input
        type="number"
        class="form-control form-control-sm"
        ${targetAttr}
        data-step-field-input="true"
        value="${escapeHtml(value)}"
      >
    `;
  }

  return `
    <input
      type="text"
      class="form-control form-control-sm"
      ${targetAttr}
      data-step-field-input="true"
      value="${escapeHtml(value)}"
    >
  `;
}

function renderFieldRow(stepId, field, currentValue, removable, runtimeContext) {
  const pickerHtml = supportsInlineVariablePicker(field.field_kind)
    ? renderInlineVariablePicker({
        actionAttribute: 'data-graph-overlay-action',
        catalog: runtimeContext.catalog,
        triggerKey: runtimeContext.triggerKey,
        availableVarNames: runtimeContext.availableVarNames,
      })
    : '';
  const suggestions = getStepFieldSuggestions(runtimeContext.stepType, field.key);

  return `
    <div class="border rounded p-2 mb-2" data-step-field-row="${escapeHtml(field.key)}">
      <div class="d-flex align-items-start justify-content-between gap-2 mb-1">
        <label class="form-label form-label-sm mb-0">${escapeHtml(field.title || field.key)}</label>
        ${field.required ? '<span class="small text-muted">required</span>' : '<span class="small text-muted">optional</span>'}
      </div>

      ${field.description ? `<div class="small text-muted mb-2">${escapeHtml(field.description)}</div>` : ''}

      <div class="mb-2"${pickerHtml ? ' data-inline-variable-scope="true"' : ''}>
        ${renderFieldInput(field, currentValue, {
          targetAttr: pickerHtml ? 'data-inline-variable-target="value"' : '',
        })}
        ${pickerHtml}
      </div>

      ${
        suggestions.length
          ? `
            <div class="wf2-structured-hint-card">
              <div class="wf2-structured-hint-title">Suggested snippets</div>
              <div class="wf2-structured-hint-chip-row">
                ${suggestions
                  .map(
                    (item) => `
                      <button
                        type="button"
                        class="btn btn-sm btn-outline-secondary"
                        data-graph-overlay-action="apply-step-field-suggestion"
                        data-suggestion-value="${escapeHtml(encodeURIComponent(item.value))}"
                        title="${escapeHtml(item.description)}"
                      >
                        ${escapeHtml(item.label)}
                      </button>
                    `,
                  )
                  .join('')}
              </div>
            </div>
          `
          : ''
      }

      ${
        removable
          ? `
            <div class="d-flex gap-2">
              <button
                type="button"
                class="btn btn-sm btn-outline-danger"
                data-graph-overlay-action="remove-step-field"
                data-step-id="${escapeHtml(stepId)}"
                data-field-key="${escapeHtml(field.key)}"
              >
                Remove
              </button>
            </div>
          `
          : ''
      }
    </div>
  `;
}

function renderFieldSectionContent(rowsHtml, { emptyLabel, hasRows }) {
  return `
    <div data-step-field-section="true">
      ${rowsHtml}
      ${hasRows ? '' : `<div class="small text-muted">${escapeHtml(emptyLabel)}</div>`}
    </div>
  `;
}

function renderMissingOptionalFieldButtons(stepId, fields) {
  if (!fields.length) {
    return '<div class="small text-muted">No missing optional fields.</div>';
  }

  return `
    <div class="d-flex flex-wrap gap-2">
      ${fields
        .map(
          (field) => `
            <button
              type="button"
              class="btn btn-sm btn-outline-primary"
              data-graph-overlay-action="add-optional-field"
              data-step-id="${escapeHtml(stepId)}"
              data-field-key="${escapeHtml(field.key)}"
            >
              Add ${escapeHtml(field.title || field.key)}
            </button>
          `,
        )
        .join('')}
    </div>
  `;
}

function renderApprovalOutcomePresetButtons() {
  return `
    <div class="d-flex flex-wrap gap-2">
      ${APPROVAL_OUTCOME_PRESETS
        .map(
          (preset) => `
            <button
              type="button"
              class="btn btn-sm btn-outline-secondary"
              data-graph-overlay-action="apply-approval-outcome-preset"
              data-approved-outcome="${escapeHtml(preset.approved)}"
              data-rejected-outcome="${escapeHtml(preset.rejected)}"
              title="${escapeHtml(preset.description)}"
            >
              ${escapeHtml(preset.label)}
            </button>
          `,
        )
        .join('')}
    </div>
  `;
}

function encodeApplyPath(path) {
  return escapeHtml(JSON.stringify(Array.isArray(path) ? path : []));
}

function formatApplyScalar(value) {
  if (value === undefined || value === null) {
    return '';
  }

  if (typeof value === 'string') {
    return value;
  }

  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function renderGraphButton(action, label, extraAttrs = '', variant = 'outline-primary') {
  return `
    <button
      type="button"
      class="btn btn-sm btn-${escapeHtml(variant)}"
      data-graph-overlay-action="${escapeHtml(action)}"${extraAttrs}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function renderApplyOperatorOptions(catalog, currentOperator) {
  return getOperatorOptions(catalog)
    .map((operatorName) => {
      const selected = operatorName === currentOperator ? ' selected' : '';
      return `<option value="${escapeHtml(operatorName)}"${selected}>${escapeHtml(operatorName)}</option>`;
    })
    .join('');
}

function renderApplyNodeHeader({ catalog, operator, ruleIndex, path, allowRemove }) {
  const encodedPath = encodeApplyPath(path);

  return `
    <div class="wf2-cond-header-row">
      <div class="wf2-cond-header-main">
        <label class="form-label form-label-sm mb-1">Operator</label>
        <select class="form-select form-select-sm wf2-cond-operator-select" data-apply-node-operator-input="true">
          ${renderApplyOperatorOptions(catalog, operator || 'compare')}
        </select>
      </div>
      <div class="wf2-cond-header-actions">
        ${renderGraphButton(
          'set-apply-node-operator',
          'Apply',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}
        ${
          allowRemove
            ? renderGraphButton(
                path.length ? 'remove-apply-child' : 'remove-apply-rule',
                path.length ? 'Remove' : 'Remove rule',
                path.length
                  ? ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`
                  : ` data-apply-rule-index="${ruleIndex}"`,
                'outline-danger',
              )
            : ''
        }
      </div>
    </div>
  `;
}

function renderApplyAddChildControls(ruleIndex, path) {
  const encodedPath = encodeApplyPath(path);

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
        ${renderGraphButton(
          'add-apply-child',
          'Add',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}
      </div>
    </div>
  `;
}

function renderApplyConditionNode({ catalog, node, ruleIndex, path = [], isRoot = false }) {
  const operator = getConditionOperator(node) || 'compare';
  const encodedPath = encodeApplyPath(path);
  const description = getOperatorDescription(operator);
  let bodyHtml = '';

  if (operator === 'exists') {
    bodyHtml = `
      <div class="wf2-inline-save-row">
        <div class="wf2-inline-save-input">
          <label class="form-label form-label-sm mb-1">Value path</label>
          <input
            type="text"
            class="form-control form-control-sm font-monospace"
            data-apply-exists-input="true"
            value="${escapeHtml(node?.exists || '')}"
          >
        </div>
        <div class="wf2-inline-save-action">
          <label class="form-label form-label-sm mb-1 d-block">&nbsp;</label>
          ${renderGraphButton(
            'save-apply-exists',
            'Save',
            ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
          )}
        </div>
      </div>
    `;
  } else if (operator === 'compare') {
    const compare = node?.compare && typeof node.compare === 'object' ? node.compare : {};
    bodyHtml = `
      <div class="wf2-compare-grid">
        <div>
          <label class="form-label form-label-sm mb-1">Left</label>
          <input
            type="text"
            class="form-control form-control-sm font-monospace"
            data-apply-compare-left="true"
            value="${escapeHtml(compare.left || '')}"
          >
        </div>
        <div>
          <label class="form-label form-label-sm mb-1">Op</label>
          <select class="form-select form-select-sm" data-apply-compare-op="true">
            ${getCompareOps(catalog)
              .map((op) => {
                const selected = op === compare.op ? ' selected' : '';
                return `<option value="${escapeHtml(op)}"${selected}>${escapeHtml(op)}</option>`;
              })
              .join('')}
          </select>
        </div>
        <div>
          <label class="form-label form-label-sm mb-1">Right</label>
          <input
            type="text"
            class="form-control form-control-sm font-monospace"
            data-apply-compare-right="true"
            value="${escapeHtml(formatApplyScalar(compare.right))}"
          >
        </div>
      </div>
      <div class="mt-2">
        ${renderGraphButton(
          'save-apply-compare',
          'Save compare',
          ` data-apply-rule-index="${ruleIndex}" data-apply-node-path="${encodedPath}"`,
        )}
      </div>
    `;
  } else if (operator === 'not') {
    bodyHtml = `
      <div class="wf2-cond-node-nested">
        ${renderApplyConditionNode({
          catalog,
          node: node?.not,
          ruleIndex,
          path: [...path, 0],
          isRoot: false,
        })}
      </div>
    `;
  } else if (operator === 'and' || operator === 'or') {
    const children = Array.isArray(node?.[operator]) ? node[operator] : [];
    bodyHtml = `
      <div class="wf2-cond-node-nested">
        ${
          children.length
            ? children
                .map((child, index) =>
                  renderApplyConditionNode({
                    catalog,
                    node: child,
                    ruleIndex,
                    path: [...path, index],
                    isRoot: false,
                  }),
                )
                .join('')
            : '<div class="small text-muted">No nested conditions yet.</div>'
        }
      </div>
      ${renderApplyAddChildControls(ruleIndex, path)}
    `;
  } else {
    bodyHtml = '<div class="small text-muted">Unsupported condition node. Change the operator to replace it.</div>';
  }

  return `
    <div class="wf2-cond-node" data-apply-scope="true" data-apply-node-path="${encodedPath}">
      ${renderApplyNodeHeader({
        catalog,
        operator,
        ruleIndex,
        path,
        allowRemove: true,
      })}
      ${description ? `<div class="small text-muted mb-2">${escapeHtml(description)}</div>` : ''}
      ${bodyHtml}
    </div>
  `;
}

function renderApplyRule(rule, index, catalog) {
  return `
    <div class="wf2-apply-rule-card">
      <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
        <div>
          <div class="fw-semibold">Apply rule ${index + 1}</div>
          <div class="small text-muted">Rules are combined as a top-level AND.</div>
        </div>
      </div>
      ${renderApplyConditionNode({
        catalog,
        node: rule,
        ruleIndex: index,
        path: [],
        isRoot: true,
      })}
    </div>
  `;
}

function renderApplyNodeOverlay({ graph, layout, viewport, catalog, node }) {
  const pos = layout.positions.get(node.id);
  if (!pos) {
    return '';
  }

  const fitted = fitPanelToViewport(viewport, {
    panelWidth: 680,
    panelHeight: 820,
    minWidth: 420,
    minHeight: 360,
  });
  const { left, top } = placePanelNearNode(viewport, pos, {
    panelWidth: fitted.width,
    panelHeight: fitted.height,
  });

  const rules = Array.isArray(node.apply_rules) ? node.apply_rules : [];
  const addButtons = ['compare', 'exists', 'and', 'or', 'not']
    .map((operator) =>
      renderGraphButton(
        'add-apply-rule',
        `Add ${operator}`,
        ` data-apply-operator="${escapeHtml(operator)}"`,
      ),
    )
    .join('');

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-node wf2-graph-overlay-shell" style="left:${left}px; top:${top}px; width:${fitted.width}px; height:${fitted.height}px; max-width:${fitted.maxWidth}px; max-height:${fitted.maxHeight}px;">
      <div class="wf2-graph-floating-header">
        <div>
          <div class="wf2-graph-floating-kicker">Apply editor</div>
          <div class="wf2-graph-floating-title">Workflow preconditions</div>
          <div class="wf2-graph-floating-subtitle">Edit the top-level apply rules that gate this workflow before the start step runs.</div>
        </div>
        ${renderCloseButton()}
      </div>

      <div class="wf2-graph-floating-meta">
        ${renderMetaPill('Rules', String(rules.length))}
        ${renderMetaPill('Effect', rules.length ? 'gated' : 'always runs')}
        ${renderMetaPill('Start', graph?.start || '-')}
      </div>

      <div class="wf2-graph-floating-body">
        ${renderSection(
          'Add rule',
          `<div class="d-flex flex-wrap gap-2">${addButtons}</div>`,
          'Apply rules are saved to the top-level apply block in YAML.',
        )}

        ${renderSection(
          'Rules',
          rules.length
            ? rules.map((rule, index) => renderApplyRule(rule, index, catalog)).join('')
            : '<div class="small text-muted">No preconditions configured.</div>',
          'All listed rules must match before the workflow starts.',
        )}
      </div>
    </div>
  `;
}

function renderTriggerOption(eventSpec, currentTriggerKey) {
  const key = String(eventSpec?.key || '');
  const label = eventSpec?.title || key;
  const group = eventSpec?.group_title ? ` · ${eventSpec.group_title}` : '';
  const selected = key === currentTriggerKey ? ' selected' : '';

  return `<option value="${escapeHtml(key)}"${selected}>${escapeHtml(`${label}${group}`)}</option>`;
}

function findSourceEntry(entries, rawValue) {
  return (entries || []).find((entry) => String(entry?.id) === String(rawValue)) || null;
}

function sourceEntryMeta(entry, sourceKind) {
  if (!entry) {
    return 'Not found in current Trustpoint data';
  }

  if (sourceKind === 'ca_ids') {
    return ['ID ' + entry.id, entry.type || '', entry.active === false ? 'inactive' : '']
      .filter(Boolean)
      .join(' · ');
  }

  if (sourceKind === 'domain_ids') {
    return ['ID ' + entry.id, entry.issuing_ca_title ? `CA ${entry.issuing_ca_title}` : '', entry.active === false ? 'inactive' : '']
      .filter(Boolean)
      .join(' · ');
  }

  return ['ID ' + entry.id, entry.domain_title ? `Domain ${entry.domain_title}` : '', entry.serial_number ? `SN ${entry.serial_number}` : '']
    .filter(Boolean)
    .join(' · ');
}

function renderSelectedSourceRows({ sourceKind, selectedValues, entries }) {
  if (!Array.isArray(selectedValues) || !selectedValues.length) {
    return '<div class="small text-muted">No filters selected.</div>';
  }

  return `
    <div class="wf2-graph-trigger-source-list">
      ${selectedValues
        .map((value) => {
          const entry = findSourceEntry(entries, value);
          const title = entry?.title || String(value);

          return `
            <div class="wf2-graph-trigger-source-row">
              <div>
                <div class="fw-semibold">${escapeHtml(title)}</div>
                <div class="small text-muted">${escapeHtml(sourceEntryMeta(entry, sourceKind))}</div>
              </div>
              <button
                type="button"
                class="btn btn-sm btn-outline-danger"
                data-graph-overlay-action="remove-trigger-source-value"
                data-trigger-source-kind="${escapeHtml(sourceKind)}"
                data-trigger-source-value="${escapeHtml(String(value))}"
              >
                Remove
              </button>
            </div>
          `;
        })
        .join('')}
    </div>
  `;
}

function renderSourcePicker({ title, sourceKind, entries, selectedValues }) {
  const selected = new Set((selectedValues || []).map((value) => String(value)));
  const options = (entries || [])
    .filter((entry) => !selected.has(String(entry?.id)))
    .map((entry) => `<option value="${escapeHtml(String(entry.id))}">${escapeHtml(entry.title || String(entry.id))}</option>`)
    .join('');

  return `
    <div class="wf2-graph-trigger-source-group" data-trigger-source-group="${escapeHtml(sourceKind)}">
      <div class="fw-semibold mb-2">${escapeHtml(title)}</div>
      <div class="wf2-graph-editor-inline-row mb-2">
        <select class="form-select form-select-sm" data-trigger-source-select="${escapeHtml(sourceKind)}">
          <option value="">${escapeHtml(`Add ${title.toLowerCase()}`)}</option>
          ${options}
        </select>
        <button
          type="button"
          class="btn btn-sm btn-outline-primary"
          data-graph-overlay-action="add-trigger-source-selected"
          data-trigger-source-kind="${escapeHtml(sourceKind)}"
          ${options ? '' : 'disabled'}
        >
          Add
        </button>
      </div>
      ${renderSelectedSourceRows({ sourceKind, selectedValues, entries })}
    </div>
  `;
}

function renderTriggerNodeOverlay({ layout, viewport, catalog, node }) {
  const pos = layout.positions.get(node.id);
  if (!pos) {
    return '';
  }

  const fitted = fitPanelToViewport(viewport, {
    panelWidth: 620,
    panelHeight: 760,
    minWidth: 420,
    minHeight: 360,
  });
  const { left, top } = placePanelNearNode(viewport, pos, {
    panelWidth: fitted.width,
    panelHeight: fitted.height,
  });

  const triggerKey = node.trigger_key || '';
  const triggerSpec = findTriggerSpec(catalog, triggerKey);
  const sources = node.trigger_sources || {};
  const sourceCatalog = catalog?.trigger_sources || {};
  const eventOptions = (catalog?.events || [])
    .slice()
    .sort((left, right) => String(left?.title || left?.key || '').localeCompare(String(right?.title || right?.key || '')))
    .map((eventSpec) => renderTriggerOption(eventSpec, triggerKey))
    .join('');

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-node wf2-graph-overlay-shell" style="left:${left}px; top:${top}px; width:${fitted.width}px; height:${fitted.height}px; max-width:${fitted.maxWidth}px; max-height:${fitted.maxHeight}px;">
      <div class="wf2-graph-floating-header">
        <div>
          <div class="wf2-graph-floating-kicker">Trigger editor</div>
          <div class="wf2-graph-floating-title">${escapeHtml(triggerSpec?.title || triggerKey || 'Workflow trigger')}</div>
          <div class="wf2-graph-floating-subtitle">${escapeHtml(triggerSpec?.description || 'Choose the event that starts this workflow.')}</div>
        </div>
        ${renderCloseButton()}
      </div>

      <div class="wf2-graph-floating-meta">
        ${renderMetaPill('Trigger', triggerKey || '-')}
        ${renderMetaPill('Scope', node.scope_summary || '-')}
      </div>

      <div class="wf2-graph-floating-body">
        ${renderSection(
          'Event',
          `
            <div class="wf2-graph-editor-inline-row">
              <select class="form-select form-select-sm" data-trigger-select="true">
                <option value="">Choose trigger</option>
                ${eventOptions}
              </select>
              <button type="button" class="btn btn-sm btn-primary" data-graph-overlay-action="save-trigger-on">
                Apply
              </button>
            </div>
          `,
          'Changing the trigger updates trigger.on in YAML.',
        )}

        ${renderSection(
          'Source scope',
          `
            <div class="wf2-guide-segmented">
              <button
                type="button"
                class="btn btn-sm ${sources.trustpoint ? 'btn-primary' : 'btn-outline-primary'}"
                data-graph-overlay-action="set-trigger-trustpoint"
                data-trigger-trustpoint="true"
                ${sources.trustpoint ? 'disabled' : ''}
              >
                All sources
              </button>
              <button
                type="button"
                class="btn btn-sm ${sources.trustpoint ? 'btn-outline-primary' : 'btn-primary'}"
                data-graph-overlay-action="set-trigger-trustpoint"
                data-trigger-trustpoint="false"
                ${sources.trustpoint ? '' : 'disabled'}
              >
                Scoped sources
              </button>
            </div>
            <div class="small text-muted mt-2">
              ${sources.trustpoint ? 'Saved filters stay visible, but dispatch currently uses all sources.' : 'Only explicit CA, domain, or device filters are considered.'}
            </div>
          `,
          'Use scoped sources when only selected Trustpoint objects should emit this workflow.',
        )}

        ${renderSection(
          'Source filters',
          `
            ${renderSourcePicker({
              title: 'Certificate authorities',
              sourceKind: 'ca_ids',
              entries: sourceCatalog.cas || [],
              selectedValues: sources.ca_ids || [],
            })}
            ${renderSourcePicker({
              title: 'Domains',
              sourceKind: 'domain_ids',
              entries: sourceCatalog.domains || [],
              selectedValues: sources.domain_ids || [],
            })}
            ${renderSourcePicker({
              title: 'Devices',
              sourceKind: 'device_ids',
              entries: sourceCatalog.devices || [],
              selectedValues: sources.device_ids || [],
            })}
          `,
          'These controls edit trigger.sources in YAML.',
        )}
      </div>
    </div>
  `;
}

function renderVirtualNodeOverlay({ layout, viewport, node }) {
  const pos = layout.positions.get(node.id);
  if (!pos) {
    return '';
  }

  const fitted = fitPanelToViewport(viewport, {
    panelWidth: 460,
    panelHeight: 280,
    minWidth: 320,
    minHeight: 240,
  });
  const { left, top } = placePanelNearNode(viewport, pos, {
    panelWidth: fitted.width,
    panelHeight: fitted.height,
  });

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-node wf2-graph-overlay-shell" style="left:${left}px; top:${top}px; width:${fitted.width}px; height:${fitted.height}px; max-width:${fitted.maxWidth}px; max-height:${fitted.maxHeight}px;">
      <div class="wf2-graph-floating-header">
        <div>
          <div class="wf2-graph-floating-kicker">Virtual target</div>
          <div class="wf2-graph-floating-title">Terminal target</div>
          <div class="wf2-graph-floating-subtitle">This node is derived from the flow graph, not from a step definition.</div>
        </div>
        ${renderCloseButton()}
      </div>

      <div class="wf2-graph-floating-meta">
        ${renderMetaPill('Target', node.id)}
      </div>

      <div class="wf2-graph-floating-body">
        ${renderSection(
          'Meaning',
          '<div class="small text-muted">This is a virtual end target derived from the flow.</div>',
        )}
      </div>
    </div>
  `;
}

export function renderGraphStepEditorOverlay({
  graph,
  layout,
  viewport,
  catalog,
  node,
  stepData,
}) {
  if (node.is_trigger) {
    return renderTriggerNodeOverlay({ layout, viewport, catalog, node });
  }

  if (node.is_apply) {
    return renderApplyNodeOverlay({ graph, layout, viewport, catalog, node });
  }

  if (node.is_virtual) {
    return renderVirtualNodeOverlay({ layout, viewport, node });
  }

  const pos = layout.positions.get(node.id);
  if (!pos) {
    return '';
  }

  const fitted = fitPanelToViewport(viewport, {
    panelWidth: 680,
    panelHeight: 920,
    minWidth: 420,
    minHeight: 360,
  });
  const { left, top } = placePanelNearNode(viewport, pos, {
    panelWidth: fitted.width,
    panelHeight: fitted.height,
  });

  const stepType = String(node.type || '');
  const stepSpec = findStepSpec(catalog, stepType);
  const fieldSpecs = getFieldSpecs(catalog, stepType);

  const requiredFields = fieldSpecs.filter(
    (field) => field.required && !isSpecialManagedField(stepType, field.key),
  );

  const presentOptionalFields = fieldSpecs.filter(
    (field) =>
      !field.required &&
      hasOwn(stepData, field.key) &&
      !isSpecialManagedField(stepType, field.key),
  );

  const missingOptionalFields = fieldSpecs.filter(
    (field) =>
      !field.required &&
      !hasOwn(stepData, field.key) &&
      !isSpecialManagedField(stepType, field.key),
  );

  const requiredFieldsHtml = requiredFields.length
    ? renderFieldSectionContent(
        requiredFields
          .map((field) =>
            renderFieldRow(
              node.id,
                field,
                stepData?.[field.key],
                false,
                {
                  availableVarNames: node.available_var_names || [],
                  catalog,
                  stepType,
                  triggerKey: graph.trigger_key,
                },
              ),
          )
          .join(''),
        {
          emptyLabel: 'No simple required fields.',
          hasRows: true,
        },
      )
    : renderFieldSectionContent('', {
        emptyLabel: 'No simple required fields.',
        hasRows: false,
      });

  const presentOptionalFieldsHtml = presentOptionalFields.length
    ? renderFieldSectionContent(
        presentOptionalFields
          .map((field) =>
            renderFieldRow(
              node.id,
                field,
                stepData?.[field.key],
                true,
                {
                  availableVarNames: node.available_var_names || [],
                  catalog,
                  stepType,
                  triggerKey: graph.trigger_key,
                },
              ),
          )
          .join(''),
        {
          emptyLabel: 'No simple optional fields currently present.',
          hasRows: true,
        },
      )
    : renderFieldSectionContent('', {
        emptyLabel: 'No simple optional fields currently present.',
        hasRows: false,
      });

  const structuredHtml = renderStructuredStepFields({
    availableVarNames: node.available_var_names || [],
    triggerKey: graph.trigger_key,
    stepId: node.id,
    stepType,
    stepData,
    catalog,
  });

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-node wf2-graph-overlay-shell" style="left:${left}px; top:${top}px; width:${fitted.width}px; height:${fitted.height}px; max-width:${fitted.maxWidth}px; max-height:${fitted.maxHeight}px;">
      <div class="wf2-graph-floating-header">
        <div>
          <div class="wf2-graph-floating-kicker">Step editor</div>
          <div class="wf2-graph-floating-title">
            <code>${escapeHtml(node.id)}</code>
          </div>
          <div class="wf2-graph-floating-subtitle">
            ${escapeHtml(stepSpec?.title || stepType)} · ${escapeHtml(stepType)}
          </div>
        </div>
        ${renderCloseButton()}
      </div>

      <div class="wf2-graph-floating-meta">
        ${renderMetaPill('Type', stepType || '-')}
        ${renderMetaPill('Start', graph.start === node.id ? 'yes' : 'no')}
        ${renderMetaPill('Outcomes', Array.isArray(node.outcomes) && node.outcomes.length ? node.outcomes.join(', ') : 'none')}
      </div>

      <div class="wf2-graph-floating-body">
        ${renderSection(
          'Title',
          `
            <input
              type="text"
              class="form-control form-control-sm"
              data-node-title-input="true"
              value="${escapeHtml(stepData?.title ?? node.title ?? '')}"
            >
          `,
          'Use the node title for a concise label in the graph.',
        )}

        ${structuredHtml && stepType !== 'webhook'
          ? renderSection(
              'Managed content',
              structuredHtml,
              'These step-specific structures are easier to edit here than in raw YAML.',
            )
          : ''}

        ${stepType === 'approval'
          ? renderSection(
              'Approval outcome presets',
              renderApprovalOutcomePresetButtons(),
              'Apply a common approved/rejected naming pair before saving the step.',
            )
          : ''}

        ${renderSection(
          'Required fields',
          requiredFieldsHtml,
          'Core fields that must be present for this step to compile.',
        )}

        ${renderSection(
          'Optional fields',
          presentOptionalFieldsHtml,
          'Fields currently present on the step.',
        )}

        ${renderSection(
          'Add optional field',
          renderMissingOptionalFieldButtons(node.id, missingOptionalFields),
          'Add documented optional fields without switching back to YAML.',
        )}

        ${structuredHtml && stepType === 'webhook'
          ? renderSection(
              'Managed content',
              structuredHtml,
              'These step-specific structures are easier to edit here than in raw YAML.',
            )
          : ''}

        ${renderStepSummarySection(catalog, graph, node)}
      </div>

      <div class="wf2-graph-floating-footer">

        <button
          type="button"
          class="btn btn-sm btn-outline-primary"
          data-graph-overlay-action="set-start"
          data-step-id="${escapeHtml(node.id)}"
          ${graph.start === node.id ? 'disabled' : ''}
        >
          Set start
        </button>

        <button
          type="button"
          class="btn btn-sm btn-outline-danger"
          data-graph-overlay-action="delete-step"
          data-step-id="${escapeHtml(node.id)}"
        >
          Delete
        </button>

        <button
          type="button"
          class="btn btn-sm btn-primary ms-auto"
          data-graph-overlay-action="save-step-editor"
          data-step-id="${escapeHtml(node.id)}"
          data-step-type="${escapeHtml(stepType)}"
        >
          Save changes
        </button>
      </div>
    </div>
  `;
}
