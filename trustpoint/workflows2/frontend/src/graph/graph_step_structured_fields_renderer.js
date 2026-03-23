import { escapeHtml } from '../core/dom.js';
import { renderLogicConditionTree } from './graph_logic_condition_tree_renderer.js';

function renderButton(action, label, extraAttrs = '') {
  return `
    <button
      type="button"
      class="btn btn-sm btn-outline-primary"
      data-graph-overlay-action="${escapeHtml(action)}"${extraAttrs}
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
      data-graph-overlay-action="${escapeHtml(action)}"${extraAttrs}
    >
      ${escapeHtml(label)}
    </button>
  `;
}

function renderLogicCasesEditor(stepId, stepData, catalog) {
  const cases = Array.isArray(stepData?.cases) ? stepData.cases : [];

  const rows = cases
    .map((item, index) => {
      const whenNode =
        item?.when && typeof item.when === 'object' && !Array.isArray(item.when)
          ? item.when
          : {
              compare: {
                left: '${vars.value}',
                op: '==',
                right: '',
              },
            };

      return `
        <div class="wf2-logic-case-card" data-logic-case-row="${index}">
          <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
            <div class="fw-semibold">Case ${index + 1}</div>
            ${renderDangerButton(
              'remove-logic-case',
              'Remove case',
              ` data-step-id="${escapeHtml(stepId)}" data-case-index="${index}"`,
            )}
          </div>

          ${renderLogicConditionTree({
            stepId,
            caseIndex: index,
            path: [],
            node: whenNode,
            catalog,
            nested: false,
          })}

          <div class="wf2-logic-case-outcome mt-3">
            <label class="form-label form-label-sm mb-1">Outcome</label>
            <div class="wf2-logic-case-outcome-row">
              <input
                type="text"
                class="form-control form-control-sm"
                data-logic-case-outcome-input="true"
                value="${escapeHtml(item?.outcome ?? '')}"
              >
              ${renderButton(
                'save-logic-case-outcome',
                'Save outcome',
                ` data-step-id="${escapeHtml(stepId)}" data-case-index="${index}"`,
              )}
            </div>
          </div>
        </div>
      `;
    })
    .join('');

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-2">Logic cases</div>
      ${rows || '<div class="small text-muted mb-2">No cases yet.</div>'}
      <div class="d-flex gap-2">
        ${renderButton('add-logic-case', 'Add case', ` data-step-id="${escapeHtml(stepId)}"`)}
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-2">Default outcome</div>
      <div class="d-flex gap-2">
        <input
          type="text"
          class="form-control form-control-sm"
          data-logic-default-input="true"
          value="${escapeHtml(stepData?.default ?? '')}"
        >
        ${renderButton('save-logic-default', 'Save', ` data-step-id="${escapeHtml(stepId)}"`)}
      </div>
    </div>
  `;
}

function renderWebhookCaptureEditor(stepId, stepData) {
  const capture =
    stepData?.capture && typeof stepData.capture === 'object' && !Array.isArray(stepData.capture)
      ? stepData.capture
      : {};

  const rows = Object.entries(capture)
    .map(([target, source]) => {
      return `
        <div class="border rounded p-2 mb-2" data-capture-row="${escapeHtml(target)}">
          <div class="mb-2">
            <label class="form-label form-label-sm mb-1">Target var</label>
            <input
              type="text"
              class="form-control form-control-sm"
              data-capture-target-input="true"
              value="${escapeHtml(target)}"
            >
          </div>

          <div class="mb-2">
            <label class="form-label form-label-sm mb-1">Source</label>
            <input
              type="text"
              class="form-control form-control-sm"
              data-capture-source-input="true"
              value="${escapeHtml(source)}"
            >
          </div>

          <div class="d-flex gap-2">
            ${renderButton(
              'save-webhook-capture-rule',
              'Save',
              ` data-step-id="${escapeHtml(stepId)}" data-capture-target="${escapeHtml(target)}"`,
            )}
            ${renderDangerButton(
              'remove-webhook-capture-rule',
              'Remove',
              ` data-step-id="${escapeHtml(stepId)}" data-capture-target="${escapeHtml(target)}"`,
            )}
          </div>
        </div>
      `;
    })
    .join('');

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-2">Capture rules</div>
      ${rows || '<div class="small text-muted mb-2">No capture rules yet.</div>'}
      <div class="d-flex gap-2">
        ${renderButton('add-webhook-capture-rule', 'Add capture rule', ` data-step-id="${escapeHtml(stepId)}"`)}
      </div>
    </div>
  `;
}

function renderComputeAssignmentsEditor(stepId, stepData, catalog) {
  const assignments =
    stepData?.set && typeof stepData.set === 'object' && !Array.isArray(stepData.set)
      ? stepData.set
      : {};

  const operators = catalog?.dsl?.compute?.operators || [];

  const rows = Object.entries(assignments)
    .map(([target, spec]) => {
      const operator = spec && typeof spec === 'object' ? Object.keys(spec)[0] || 'add' : 'add';
      const args = spec && typeof spec === 'object' && Array.isArray(spec[operator]) ? spec[operator] : [];

      return `
        <div class="border rounded p-2 mb-2" data-compute-row="${escapeHtml(target)}">
          <div class="mb-2">
            <label class="form-label form-label-sm mb-1">Target</label>
            <input
              type="text"
              class="form-control form-control-sm"
              data-compute-target-input="true"
              value="${escapeHtml(target)}"
            >
          </div>

          <div class="mb-2">
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

          <div class="mb-2">
            <label class="form-label form-label-sm mb-1">Args (one per line)</label>
            <textarea
              class="form-control form-control-sm font-monospace"
              rows="4"
              data-compute-args-input="true"
              spellcheck="false"
            >${escapeHtml(args.map((arg) => String(arg)).join('\n'))}</textarea>
          </div>

          <div class="d-flex gap-2">
            ${renderButton(
              'save-compute-assignment',
              'Save',
              ` data-step-id="${escapeHtml(stepId)}" data-compute-target="${escapeHtml(target)}"`,
            )}
            ${renderDangerButton(
              'remove-compute-assignment',
              'Remove',
              ` data-step-id="${escapeHtml(stepId)}" data-compute-target="${escapeHtml(target)}"`,
            )}
          </div>
        </div>
      `;
    })
    .join('');

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-2">Compute assignments</div>
      ${rows || '<div class="small text-muted mb-2">No assignments yet.</div>'}
      <div class="d-flex gap-2">
        ${renderButton('add-compute-assignment', 'Add assignment', ` data-step-id="${escapeHtml(stepId)}"`)}
      </div>
    </div>
  `;
}

function renderSetVarsEditor(stepId, stepData) {
  const varsMap =
    stepData?.vars && typeof stepData.vars === 'object' && !Array.isArray(stepData.vars)
      ? stepData.vars
      : {};

  const rows = Object.entries(varsMap)
    .map(([key, value]) => {
      return `
        <div class="border rounded p-2 mb-2" data-set-var-row="${escapeHtml(key)}">
          <div class="mb-2">
            <label class="form-label form-label-sm mb-1">Var name</label>
            <input
              type="text"
              class="form-control form-control-sm"
              data-set-var-key-input="true"
              value="${escapeHtml(key)}"
            >
          </div>

          <div class="mb-2">
            <label class="form-label form-label-sm mb-1">Value</label>
            <input
              type="text"
              class="form-control form-control-sm"
              data-set-var-value-input="true"
              value="${escapeHtml(value)}"
            >
          </div>

          <div class="d-flex gap-2">
            ${renderButton(
              'save-set-var-entry',
              'Save',
              ` data-step-id="${escapeHtml(stepId)}" data-set-var-key="${escapeHtml(key)}"`,
            )}
            ${renderDangerButton(
              'remove-set-var-entry',
              'Remove',
              ` data-step-id="${escapeHtml(stepId)}" data-set-var-key="${escapeHtml(key)}"`,
            )}
          </div>
        </div>
      `;
    })
    .join('');

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-2">Vars</div>
      ${rows || '<div class="small text-muted mb-2">No vars yet.</div>'}
      <div class="d-flex gap-2">
        ${renderButton('add-set-var-entry', 'Add var', ` data-step-id="${escapeHtml(stepId)}"`)}
      </div>
    </div>
  `;
}

export function renderStructuredStepFields({
  stepId,
  stepType,
  stepData,
  catalog,
}) {
  if (stepType === 'logic') {
    return renderLogicCasesEditor(stepId, stepData, catalog);
  }

  if (stepType === 'webhook') {
    return renderWebhookCaptureEditor(stepId, stepData);
  }

  if (stepType === 'compute') {
    return renderComputeAssignmentsEditor(stepId, stepData, catalog);
  }

  if (stepType === 'set') {
    return renderSetVarsEditor(stepId, stepData);
  }

  return '';
}