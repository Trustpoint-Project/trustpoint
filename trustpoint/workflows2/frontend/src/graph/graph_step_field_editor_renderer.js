import { escapeHtml } from '../core/dom.js';
import { renderStructuredStepFields } from './graph_step_structured_fields_renderer.js';

function clamp(value, min, max) {
  return Math.max(min, Math.min(value, max));
}

function hasOwn(obj, key) {
  return !!obj && Object.prototype.hasOwnProperty.call(obj, key);
}

function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
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

function renderFieldInput(field, currentValue) {
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
        data-step-field-input="true"
      >${escapeHtml(value)}</textarea>
    `;
  }

  if (field.field_kind === 'int') {
    return `
      <input
        type="number"
        class="form-control form-control-sm"
        data-step-field-input="true"
        value="${escapeHtml(value)}"
      >
    `;
  }

  return `
    <input
      type="text"
      class="form-control form-control-sm"
      data-step-field-input="true"
      value="${escapeHtml(value)}"
    >
  `;
}

function renderFieldRow(stepId, field, currentValue, removable) {
  return `
    <div class="border rounded p-2 mb-2" data-step-field-row="${escapeHtml(field.key)}">
      <div class="d-flex align-items-start justify-content-between gap-2 mb-1">
        <label class="form-label form-label-sm mb-0">${escapeHtml(field.title || field.key)}</label>
        ${field.required ? '<span class="small text-muted">required</span>' : '<span class="small text-muted">optional</span>'}
      </div>

      ${field.description ? `<div class="small text-muted mb-2">${escapeHtml(field.description)}</div>` : ''}

      <div class="mb-2">
        ${renderFieldInput(field, currentValue)}
      </div>

      <div class="d-flex gap-2">
        <button
          type="button"
          class="btn btn-sm btn-outline-primary"
          data-graph-overlay-action="save-step-field"
          data-step-id="${escapeHtml(stepId)}"
          data-field-key="${escapeHtml(field.key)}"
        >
          Save
        </button>

        ${
          removable
            ? `
              <button
                type="button"
                class="btn btn-sm btn-outline-danger"
                data-graph-overlay-action="remove-step-field"
                data-step-id="${escapeHtml(stepId)}"
                data-field-key="${escapeHtml(field.key)}"
              >
                Remove
              </button>
            `
            : ''
        }
      </div>
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

function renderVirtualNodeOverlay({ layout, node }) {
  const pos = layout.positions.get(node.id);
  if (!pos) {
    return '';
  }

  const left = clamp(pos.x + pos.w + 12, 8, layout.width - 372);
  const top = clamp(pos.y, 8, layout.height - 200);

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-node" style="left:${left}px; top:${top}px;">
      <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
        <div class="wf2-graph-floating-title">Terminal target</div>
        ${renderCloseButton()}
      </div>

      <div class="small text-muted mb-2">
        <code>${escapeHtml(node.id)}</code>
      </div>

      <div class="small text-muted">
        This is a virtual end target derived from the flow.
      </div>
    </div>
  `;
}

export function renderGraphStepEditorOverlay({
  graph,
  layout,
  catalog,
  node,
  stepData,
}) {
  if (node.is_virtual) {
    return renderVirtualNodeOverlay({ layout, node });
  }

  const pos = layout.positions.get(node.id);
  if (!pos) {
    return '';
  }

  const left = clamp(pos.x + pos.w + 12, 8, layout.width - 372);
  const top = clamp(pos.y, 8, layout.height - 320);

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
    ? requiredFields
        .map((field) =>
          renderFieldRow(
            node.id,
            field,
            stepData?.[field.key],
            false,
          ),
        )
        .join('')
    : '<div class="small text-muted">No simple required fields.</div>';

  const presentOptionalFieldsHtml = presentOptionalFields.length
    ? presentOptionalFields
        .map((field) =>
          renderFieldRow(
            node.id,
            field,
            stepData?.[field.key],
            true,
          ),
        )
        .join('')
    : '<div class="small text-muted">No simple optional fields currently present.</div>';

  const structuredHtml = renderStructuredStepFields({
    stepId: node.id,
    stepType,
    stepData,
    catalog,
  });

  return `
    <div class="wf2-graph-floating-card wf2-graph-floating-node" style="left:${left}px; top:${top}px;">
      <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
        <div class="wf2-graph-floating-title">
          Step: <code>${escapeHtml(node.id)}</code>
        </div>
        ${renderCloseButton()}
      </div>

      <div class="small text-muted mb-3">
        ${escapeHtml(stepSpec?.title || stepType)} &middot; ${escapeHtml(stepType)}
      </div>

      <div class="mb-3">
        <label class="form-label form-label-sm mb-1">Title</label>
        <div class="d-flex gap-2">
          <input
            type="text"
            class="form-control form-control-sm"
            data-node-title-input="true"
            value="${escapeHtml(stepData?.title ?? node.title ?? '')}"
          >
          <button
            type="button"
            class="btn btn-sm btn-outline-primary"
            data-graph-overlay-action="save-node-title"
            data-step-id="${escapeHtml(node.id)}"
          >
            Save
          </button>
        </div>
      </div>

      ${structuredHtml}

      <div class="mb-3">
        <div class="fw-semibold mb-2">Required fields</div>
        ${requiredFieldsHtml}
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-2">Optional fields</div>
        ${presentOptionalFieldsHtml}
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-2">Add optional field</div>
        ${renderMissingOptionalFieldButtons(node.id, missingOptionalFields)}
      </div>

      <div class="d-flex flex-wrap gap-2">
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
      </div>
    </div>
  `;
}