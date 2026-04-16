import { escapeHtml } from '../shared/dom.js';
import { renderStructuredStepFields } from './graph_step_structured_fields_renderer.js';
import { fitPanelToViewport, placePanelNearNode } from './graph_overlay_position.js';
import { renderInlineVariablePicker } from '../variables/inline_variable_picker.js';
import { getStepFieldSuggestions } from '../document/step_field_suggestions.js';
import { APPROVAL_OUTCOME_PRESETS } from '../document/approval_outcome_presets.js';

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
