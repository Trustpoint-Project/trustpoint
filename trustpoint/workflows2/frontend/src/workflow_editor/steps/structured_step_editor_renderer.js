import { escapeHtml } from '../shared/dom.js';
import { renderLogicStepEditor } from '../logic/logic_step_editor_renderer.js';
import { WEBHOOK_CAPTURE_SOURCE_OPTIONS } from '../document/webhook_capture_sources.js';
import { renderInlineVariablePicker } from '../variables/inline_variable_picker.js';

function normalizeSetVarDisplayKey(key) {
  const trimmed = String(key || '').trim();
  if (!trimmed) {
    return 'vars.result';
  }

  return trimmed.startsWith('vars.') ? trimmed : `vars.${trimmed}`;
}

function renderButton(actionAttribute, action, label, extraAttrs = '', tone = 'primary', disabled = false) {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-${tone}"
      ${actionAttribute}="${escapeHtml(action)}"${extraAttrs}${disabled ? ' disabled' : ''}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function renderRowShell({
  label,
  description = '',
  body,
  footer,
  rowAttr,
}) {
  return `
    <div class="wf2-structured-item"${rowAttr ? ` ${rowAttr}` : ''}>
      <div class="wf2-structured-item-head">
        <div>
          <div class="wf2-structured-item-title">${escapeHtml(label)}</div>
          ${description ? `<div class="wf2-structured-item-description">${escapeHtml(description)}</div>` : ''}
        </div>
      </div>

      <div class="wf2-structured-item-body">
        ${body}
      </div>

      <div class="wf2-structured-item-actions">
        ${footer}
      </div>
    </div>
  `;
}

function renderSectionActions(content) {
  return `<div class="wf2-structured-section-actions">${content}</div>`;
}

function renderWebhookCaptureSourcePicker(actionAttribute, currentValue = '') {
  return `
    <div class="wf2-structured-hint-card">
      <div class="wf2-structured-hint-title">Known response sources</div>
      <div class="wf2-structured-hint-description">
        Pick a documented response source or use a dotted path like <code>body.some_value</code>.
      </div>
      <div class="wf2-structured-hint-chip-row">
        ${WEBHOOK_CAPTURE_SOURCE_OPTIONS
          .map((item) =>
            renderButton(
              actionAttribute,
              'apply-webhook-capture-source',
              item.value,
              ` data-capture-source-value="${escapeHtml(item.value)}" title="${escapeHtml(item.description)}"`,
              currentValue === item.value ? 'primary' : 'secondary',
            ),
          )
          .join('')}
      </div>
    </div>
  `;
}

function renderWebhookCaptureReference() {
  return `
    <div class="wf2-structured-hint-card">
      <div class="wf2-structured-hint-title">Capture reference</div>
      <div class="wf2-structured-hint-list">
        ${WEBHOOK_CAPTURE_SOURCE_OPTIONS
          .map(
            (item) => `
              <div class="wf2-structured-hint-list-item">
                <code>${escapeHtml(item.value)}</code>
                <span>${escapeHtml(item.description)}</span>
              </div>
            `,
          )
          .join('')}
      </div>
    </div>
  `;
}

function renderWebhookCaptureEditor({ actionAttribute, saveMode, stepId, stepData }) {
  const capture =
    stepData?.capture && typeof stepData.capture === 'object' && !Array.isArray(stepData.capture)
      ? stepData.capture
      : {};

  const entries = Object.entries(capture);
  const rows = entries
    .map(([target, source]) =>
      renderRowShell({
        label: target,
        description: 'Capture a webhook response value into a workflow variable.',
        rowAttr: `data-capture-row="${escapeHtml(target)}"`,
        body: `
          <div class="wf2-structured-form-grid">
            <div class="wf2-structured-field">
              <label class="form-label form-label-sm mb-1">Target var</label>
              <input
                type="text"
                class="form-control form-control-sm"
                data-capture-target-input="true"
                value="${escapeHtml(target)}"
              >
            </div>

            <div class="wf2-structured-field">
              <label class="form-label form-label-sm mb-1">Source</label>
              <input
                type="text"
                class="form-control form-control-sm"
                data-capture-source-input="true"
                value="${escapeHtml(source)}"
              >
            </div>
          </div>

          ${renderWebhookCaptureSourcePicker(actionAttribute, String(source || ''))}
        `,
        footer: renderButton(
          actionAttribute,
          'remove-webhook-capture-rule',
          'Remove',
          ` data-step-id="${escapeHtml(stepId)}" data-capture-target="${escapeHtml(target)}"`,
          'danger',
        ),
      }),
    )
    .join('');

  return `
    <div class="wf2-structured-section" data-structured-step-section="webhook-capture">
      <div class="wf2-structured-section-header">
        <div>
          <div class="wf2-structured-section-title">Capture rules</div>
          <div class="wf2-structured-section-description">
            Map response fields like status, body, or headers into workflow vars.
          </div>
        </div>
      </div>

      ${renderWebhookCaptureReference()}
      ${rows || '<div class="small text-muted mb-2">No capture rules yet.</div>'}

      ${renderSectionActions(`
        ${renderButton(actionAttribute, 'add-webhook-capture-rule', 'Add capture rule', ` data-step-id="${escapeHtml(stepId)}"`)}
        ${
          saveMode === 'footer'
            ? ''
            : renderButton(
                actionAttribute,
                'save-all-webhook-capture-rules',
                'Save all capture rules',
                ` data-step-id="${escapeHtml(stepId)}"`,
                'primary',
                !entries.length,
              )
        }
      `)}
    </div>
  `;
}

function renderComputeAssignmentsEditor({
  actionAttribute,
  availableVarNames,
  stepId,
  stepData,
  catalog,
  saveMode,
  triggerKey,
}) {
  const assignments =
    stepData?.set && typeof stepData.set === 'object' && !Array.isArray(stepData.set)
      ? stepData.set
      : {};

  const operators = catalog?.dsl?.compute?.operators || [];
  const entries = Object.entries(assignments);

  const rows = entries
    .map(([target, spec]) => {
      const operator = spec && typeof spec === 'object' ? Object.keys(spec)[0] || 'add' : 'add';
      const args = spec && typeof spec === 'object' && Array.isArray(spec[operator]) ? spec[operator] : [];

      return renderRowShell({
        label: target,
        description: 'Compute an expression and write it to a workflow variable.',
        rowAttr: `data-compute-row="${escapeHtml(target)}"`,
        body: `
          <div class="wf2-structured-form-grid">
            <div class="wf2-structured-field">
              <label class="form-label form-label-sm mb-1">Target</label>
              <input
                type="text"
                class="form-control form-control-sm"
                data-compute-target-input="true"
                value="${escapeHtml(target)}"
              >
            </div>

            <div class="wf2-structured-field">
              <label class="form-label form-label-sm mb-1">Operator</label>
              <select class="form-select form-select-sm" data-compute-operator-input="true">
                ${operators
                  .map((op) => {
                    const selected = op === operator ? ' selected' : '';
                    return `<option value="${escapeHtml(op)}"${selected}>${escapeHtml(op)}</option>`;
                  })
                  .join('')}
              </select>
            </div>

            <div class="wf2-structured-field wf2-structured-field-full" data-inline-variable-scope="true">
              <label class="form-label form-label-sm mb-1">Args (one per line)</label>
              <textarea
                class="form-control form-control-sm font-monospace"
                rows="4"
                data-inline-variable-target="value"
                data-compute-args-input="true"
                spellcheck="false"
              >${escapeHtml(args.map((arg) => String(arg)).join('\n'))}</textarea>
              ${renderInlineVariablePicker({
                actionAttribute,
                catalog,
                triggerKey,
                availableVarNames,
              })}
            </div>
          </div>
        `,
        footer: renderButton(
          actionAttribute,
          'remove-compute-assignment',
          'Remove',
          ` data-step-id="${escapeHtml(stepId)}" data-compute-target="${escapeHtml(target)}"`,
          'danger',
        ),
      });
    })
    .join('');

  return `
    <div class="wf2-structured-section" data-structured-step-section="compute-assignments">
      <div class="wf2-structured-section-header">
        <div>
          <div class="wf2-structured-section-title">Compute assignments</div>
          <div class="wf2-structured-section-description">
            Build compute expressions without hand-editing nested YAML operator blocks.
          </div>
        </div>
      </div>

      ${rows || '<div class="small text-muted mb-2">No assignments yet.</div>'}

      ${renderSectionActions(`
        ${renderButton(actionAttribute, 'add-compute-assignment', 'Add assignment', ` data-step-id="${escapeHtml(stepId)}"`)}
        ${
          saveMode === 'footer'
            ? ''
            : renderButton(
                actionAttribute,
                'save-all-compute-assignments',
                'Save all assignments',
                ` data-step-id="${escapeHtml(stepId)}"`,
                'primary',
                !entries.length,
              )
        }
      `)}
    </div>
  `;
}

function renderSetVarsEditor({
  actionAttribute,
  availableVarNames,
  stepId,
  stepData,
  catalog,
  saveMode,
  triggerKey,
}) {
  const varsMap =
    stepData?.vars && typeof stepData.vars === 'object' && !Array.isArray(stepData.vars)
      ? stepData.vars
      : {};

  const entries = Object.entries(varsMap);

  const rows = entries
    .map(([key, value]) =>
      renderRowShell({
        label: normalizeSetVarDisplayKey(key),
        description: 'Assign a literal or template value into workflow vars.',
        rowAttr: `data-set-var-row="${escapeHtml(key)}"`,
        body: `
          <div class="wf2-structured-form-grid">
            <div class="wf2-structured-field">
              <label class="form-label form-label-sm mb-1">Target var</label>
              <input
                type="text"
                class="form-control form-control-sm"
                data-set-var-key-input="true"
                value="${escapeHtml(normalizeSetVarDisplayKey(key))}"
              >
            </div>

            <div class="wf2-structured-field" data-inline-variable-scope="true">
              <label class="form-label form-label-sm mb-1">Value</label>
              <input
                type="text"
                class="form-control form-control-sm"
                data-inline-variable-target="value"
                data-set-var-value-input="true"
                value="${escapeHtml(value)}"
              >
              ${renderInlineVariablePicker({
                actionAttribute,
                catalog,
                triggerKey,
                availableVarNames,
              })}
            </div>
          </div>
        `,
        footer: renderButton(
          actionAttribute,
          'remove-set-var-entry',
          'Remove',
          ` data-step-id="${escapeHtml(stepId)}" data-set-var-key="${escapeHtml(key)}"`,
          'danger',
        ),
      }),
    )
    .join('');

  return `
    <div class="wf2-structured-section" data-structured-step-section="set-vars">
      <div class="wf2-structured-section-header">
        <div>
          <div class="wf2-structured-section-title">Variables</div>
          <div class="wf2-structured-section-description">
            Maintain workflow variable assignments in a structured editor.
          </div>
        </div>
      </div>

      ${rows || '<div class="small text-muted mb-2">No vars yet.</div>'}

      ${renderSectionActions(`
        ${renderButton(actionAttribute, 'add-set-var-entry', 'Add var', ` data-step-id="${escapeHtml(stepId)}"`)}
        ${
          saveMode === 'footer'
            ? ''
            : renderButton(
                actionAttribute,
                'save-all-set-var-entries',
                'Save all vars',
                ` data-step-id="${escapeHtml(stepId)}"`,
                'primary',
                !entries.length,
              )
        }
      `)}
    </div>
  `;
}

export function renderStructuredStepEditor({
  actionAttribute = 'data-graph-overlay-action',
  availableVarNames = [],
  catalog,
  saveMode = 'section',
  stepData,
  stepId,
  stepType,
  triggerKey = null,
}) {
  if (stepType === 'logic') {
    return renderLogicStepEditor({
      actionAttribute,
      availableVarNames,
      catalog,
      saveMode,
      stepData,
      stepId,
      triggerKey,
    });
  }

  if (stepType === 'webhook') {
    return renderWebhookCaptureEditor({
      actionAttribute,
      saveMode,
      stepId,
      stepData,
    });
  }

  if (stepType === 'compute') {
    return renderComputeAssignmentsEditor({
      actionAttribute,
      availableVarNames,
      stepId,
      stepData,
      catalog,
      saveMode,
      triggerKey,
    });
  }

  if (stepType === 'set') {
    return renderSetVarsEditor({
      actionAttribute,
      availableVarNames,
      stepId,
      stepData,
      catalog,
      saveMode,
      triggerKey,
    });
  }

  return '';
}
