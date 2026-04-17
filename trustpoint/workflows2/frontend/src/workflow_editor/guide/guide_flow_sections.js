import { escapeHtml, renderChips } from '../shared/dom.js';
import {
  renderActionButton,
  renderScalarSetterButtons,
} from './guide_ui_helpers.js';
import {
  renderGuideButtonRow,
  renderGuideSection,
} from './guide_layout.js';

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
    fieldOptions = renderGuideSection({
      title: 'Choose from-step',
      body: renderGuideButtonRow(renderScalarSetterButtons(stepIds)),
    });
  } else if (context.flowFieldKey === 'to') {
    fieldOptions = renderGuideSection({
      title: 'Choose target',
      body: renderGuideButtonRow(renderScalarSetterButtons(toOptions)),
    });
  } else if (context.flowFieldKey === 'on') {
    fieldOptions = renderGuideSection({
      title: 'Choose outcome',
      body: renderGuideButtonRow(renderScalarSetterButtons(context.currentFlowOutcomeOptions || [])),
    });
  }

  return `
    ${renderGuideSection({
      title: 'Flow',
      description: 'Add edges or fill the current edge fields without leaving YAML.',
      body: `
        <div class="mb-3">
          <div class="fw-semibold mb-1">Quick actions</div>
          ${renderGuideButtonRow(`
            ${renderActionButton('add-flow-linear-edge', 'Add linear edge')}
            ${renderActionButton('add-flow-outcome-edge', 'Add outcome edge')}
          `)}
        </div>

        <div class="mb-3">
          <div class="fw-semibold mb-1">Start from existing step</div>
          ${renderGuideButtonRow(
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
              : '<span class="text-muted">No steps available</span>',
          )}
        </div>

        <div>
          <div class="fw-semibold mb-1">Outcome edges</div>
          ${renderGuideButtonRow(
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
              : '<span class="text-muted">No outcome-producing steps available</span>',
          )}
        </div>
      `,
    })}

    ${
      currentFlowFrom || currentFlowTo || currentFlowOn
        ? `
      ${renderGuideSection({
        title: 'Current edge',
        body: `
        <div class="text-muted">
          from: <code>${escapeHtml(currentFlowFrom || '-')}</code>,
          on: <code>${escapeHtml(currentFlowOn || '-')}</code>,
          to: <code>${escapeHtml(currentFlowTo || '-')}</code>
        </div>
      `,
      })}
    `
        : ''
    }

    ${fieldOptions}

    ${renderGuideSection({
      title: 'Reference',
      body: `
        <div class="mb-3">
          <div class="fw-semibold mb-1">Known step ids</div>
          ${renderChips(stepIds, (stepId) => {
            return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
          })}
        </div>

        <div class="mb-3">
          <div class="fw-semibold mb-1">Known outcomes</div>
          ${renderChips(context.currentFlowOutcomeOptions || [], (outcome) => {
            return `<span class="wf2-chip"><strong>${escapeHtml(outcome)}</strong></span>`;
          })}
        </div>

        <div>
          <div class="fw-semibold mb-1">End targets</div>
          ${renderChips(catalog?.meta?.end_targets || [], (target) => {
            return `<span class="wf2-chip"><strong>${escapeHtml(target)}</strong></span>`;
          })}
        </div>
      `,
    })}
  `;
}
