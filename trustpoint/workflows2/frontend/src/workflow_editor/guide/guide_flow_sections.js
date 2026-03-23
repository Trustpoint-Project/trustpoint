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
      title: 'Quick actions',
      body: renderGuideButtonRow(`
        ${renderActionButton('add-flow-linear-edge', 'Add linear edge')}
        ${renderActionButton('add-flow-outcome-edge', 'Add outcome edge')}
      `),
    })}

    ${renderGuideSection({
      title: 'Add linear edge from existing step',
      body: renderGuideButtonRow(
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
      ),
    })}

    ${renderGuideSection({
      title: 'Add outcome edge from existing step',
      body: renderGuideButtonRow(
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
      ),
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
      title: 'Known step ids',
      body: renderChips(stepIds, (stepId) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
      }),
    })}

    ${renderGuideSection({
      title: 'Known outcomes',
      body: renderChips(context.currentFlowOutcomeOptions || [], (outcome) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(outcome)}</strong></span>`;
      }),
    })}

    ${renderGuideSection({
      title: 'End targets',
      body: renderChips(catalog?.meta?.end_targets || [], (target) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(target)}</strong></span>`;
      }),
    })}
  `;
}
