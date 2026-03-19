import { escapeHtml, renderChips } from '../core/dom.js';
import {
  renderActionButton,
  renderScalarSetterButtons,
} from './guide_ui_helpers.js';

export function renderFlowGuide(context, catalog) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];
  const toOptions = [...stepIds, ...(catalog?.meta?.end_targets || [])];
  const currentFlowFrom = context?.currentFlowItem?.from || null;
  const currentFlowTo = context?.currentFlowItem?.to || null;
  const currentFlowOn = context?.currentFlowItem?.on || null;

  const outcomeStepSummaries = (context?.stepSummaries || []).filter(
    (item) => Array.isArray(item.outcomes) && item.outcomes.length > 0,
  );

  let fieldOptions = '';
  if (context.flowFieldKey === 'from') {
    fieldOptions = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose from-step</div>
        ${renderScalarSetterButtons(stepIds)}
      </div>
    `;
  } else if (context.flowFieldKey === 'to') {
    fieldOptions = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose target</div>
        ${renderScalarSetterButtons(toOptions)}
      </div>
    `;
  } else if (context.flowFieldKey === 'on') {
    fieldOptions = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose outcome</div>
        ${renderScalarSetterButtons(context.currentFlowOutcomeOptions || [])}
      </div>
    `;
  }

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Quick actions</div>
      <div class="d-flex flex-wrap gap-2">
        ${renderActionButton('add-flow-linear-edge', 'Add linear edge')}
        ${renderActionButton('add-flow-outcome-edge', 'Add outcome edge')}
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Add linear edge from existing step</div>
      <div class="d-flex flex-wrap gap-2">
        ${
          stepIds.length
            ? stepIds
                .map((stepId) =>
                  renderActionButton(
                    'add-flow-linear-edge',
                    stepId,
                    ` data-flow-from="${escapeHtml(stepId)}"`,
                  ),
                )
                .join('')
            : '<span class="text-muted">No steps available</span>'
        }
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Add outcome edge from existing step</div>
      <div class="d-flex flex-wrap gap-2">
        ${
          outcomeStepSummaries.length
            ? outcomeStepSummaries
                .map((item) =>
                  renderActionButton(
                    'add-flow-outcome-edge',
                    `${item.id} (${item.outcomes.join(', ')})`,
                    ` data-flow-from="${escapeHtml(item.id)}"`,
                  ),
                )
                .join('')
            : '<span class="text-muted">No outcome-producing steps available</span>'
        }
      </div>
    </div>

    ${
      currentFlowFrom || currentFlowTo || currentFlowOn
        ? `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Current edge</div>
        <div class="text-muted">
          from: <code>${escapeHtml(currentFlowFrom || '-')}</code>,
          on: <code>${escapeHtml(currentFlowOn || '-')}</code>,
          to: <code>${escapeHtml(currentFlowTo || '-')}</code>
        </div>
      </div>
    `
        : ''
    }

    ${fieldOptions}

    <div class="mb-3">
      <div class="fw-semibold mb-1">Known step ids</div>
      <div>${renderChips(stepIds, (stepId) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
      })}</div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Known outcomes</div>
      <div>${renderChips(context.currentFlowOutcomeOptions || [], (outcome) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(outcome)}</strong></span>`;
      })}</div>
    </div>

    <div>
      <div class="fw-semibold mb-1">End targets</div>
      <div>${renderChips(catalog?.meta?.end_targets || [], (target) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(target)}</strong></span>`;
      })}</div>
    </div>
  `;
}