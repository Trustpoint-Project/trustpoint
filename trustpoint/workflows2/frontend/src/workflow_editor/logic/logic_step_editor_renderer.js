import { escapeHtml } from '../shared/dom.js';
import { renderLogicConditionTree } from './condition_tree_renderer.js';

function renderButton(actionAttribute, action, label, extraAttrs = '', tone = 'primary') {
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

export function renderLogicStepEditor({
  actionAttribute = 'data-graph-overlay-action',
  availableVarNames = [],
  catalog,
  saveMode = 'section',
  stepData,
  stepId,
  triggerKey = null,
}) {
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
        <div class="wf2-logic-case-card" data-logic-case-row="${index}" data-wf2-scope="true">
          <div class="d-flex align-items-start justify-content-between gap-2 mb-2">
            <div class="fw-semibold">Case ${index + 1}</div>
            ${renderButton(
              actionAttribute,
              'remove-logic-case',
              'Remove case',
              ` data-step-id="${escapeHtml(stepId)}" data-case-index="${index}"`,
              'danger',
            )}
          </div>

          <div data-logic-case-when="true">
            ${renderLogicConditionTree({
              actionAttribute,
              availableVarNames,
              caseIndex: index,
              catalog,
              nested: false,
              node: whenNode,
              path: [],
              saveMode,
              stepId,
              triggerKey,
            })}
          </div>

          <div class="wf2-logic-case-outcome mt-3">
            <label class="form-label form-label-sm mb-1">Outcome</label>
            <div class="wf2-logic-case-outcome-row">
              <input
                type="text"
                class="form-control form-control-sm"
                data-logic-case-outcome-input="true"
                value="${escapeHtml(item?.outcome ?? '')}"
              >
              ${
                saveMode === 'footer'
                  ? ''
                  : renderButton(
                      actionAttribute,
                      'save-logic-case-outcome',
                      'Save outcome',
                      ` data-step-id="${escapeHtml(stepId)}" data-case-index="${index}"`,
                    )
              }
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
        ${renderButton(actionAttribute, 'add-logic-case', 'Add case', ` data-step-id="${escapeHtml(stepId)}"`)}
      </div>
    </div>

    <div class="mb-0" data-wf2-scope="true">
      <div class="fw-semibold mb-2">Default outcome</div>
      <div class="d-flex gap-2">
        <input
          type="text"
          class="form-control form-control-sm"
          data-logic-default-input="true"
          value="${escapeHtml(stepData?.default ?? '')}"
        >
        ${
          saveMode === 'footer'
            ? ''
            : renderButton(actionAttribute, 'save-logic-default', 'Save', ` data-step-id="${escapeHtml(stepId)}"`)
        }
      </div>
    </div>
  `;
}
