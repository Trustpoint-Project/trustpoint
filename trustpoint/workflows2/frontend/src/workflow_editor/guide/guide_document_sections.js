import { escapeHtml, renderChips } from '../shared/dom.js';
import {
  findTriggerSpec,
  renderEventList,
  renderStepIdActions,
  renderStepTypeActions,
  renderTriggerButtons,
} from './guide_ui_helpers.js';
import { renderExpressionDsl } from './guide_dsl_sections.js';
import {
  renderGuideButtonRow,
  renderGuideMeta,
  renderGuideSection,
} from './guide_layout.js';

export function renderRootGuide(catalog) {
  return `
    ${renderGuideSection({
      title: 'What you can do here',
      description: 'Edit YAML directly and use the guide to insert documented workflow snippets without breaking structure.',
      tone: 'accent',
      body: renderGuideMeta([
        { label: 'YAML', value: 'source of truth' },
        { label: 'Guide', value: 'context-aware' },
        { label: 'Graph', value: 'draft-friendly' },
      ]),
    })}

    ${renderGuideSection({
      title: 'Expression reference',
      description: 'Runtime namespaces and helper functions available in expressions.',
      body: renderExpressionDsl(catalog),
    })}
  `;
}

export function renderTriggerGuide(context, catalog) {
  const triggerSpec = context.triggerKey
    ? findTriggerSpec(catalog, context.triggerKey)
    : null;

  if (context.area === 'trigger.on') {
    return `
      ${renderGuideSection({
        title: 'Current trigger',
        body: renderGuideMeta([
          { label: 'Selected', value: triggerSpec?.title || triggerSpec?.key || 'None' },
        ]),
      })}

      ${renderGuideSection({
        title: 'Choose trigger',
        description: 'Only documented triggers from the catalog are shown here.',
        body: renderGuideButtonRow(renderTriggerButtons(catalog?.events || [], context.triggerKey || null)),
      })}

      ${renderGuideSection({
        title: 'Available triggers',
        body: renderEventList(catalog?.events || []),
      })}
    `;
  }

  if (context.area === 'trigger.sources') {
    return renderGuideSection({
      title: 'Source filters',
      description: 'Configure whether this trigger applies trustpoint-wide, or only to selected CA IDs, domain IDs, or device IDs.',
      body: '',
    });
  }

  return renderGuideSection({
    title: 'Trigger block',
    description: 'Configure how the workflow is triggered.',
    body: '',
  });
}

export function renderWorkflowStartGuide(context) {
  return `
    ${renderGuideSection({
      title: 'Current start step',
      body: renderGuideMeta([
        { label: 'Start', value: context.currentStartStep || 'None' },
      ]),
    })}

    ${renderGuideSection({
      title: 'Set workflow start',
      description: '`workflow.start` must reference an existing step id.',
      body: renderGuideButtonRow(
        renderStepIdActions(context.stepIds || [], context.currentStartStep || null, 'set-workflow-start'),
      ),
    })}
  `;
}

export function renderStepsAreaGuide(context, catalog) {
  return `
    ${renderGuideSection({
      title: 'Add new step',
      description: 'Create a minimal step scaffold from the catalog at the current cursor position.',
      body: renderGuideButtonRow(renderStepTypeActions(catalog?.steps || [], null, 'add-step-from-type')),
    })}

    ${renderGuideSection({
      title: 'Known step ids',
      body: renderChips(context.stepIds || [], (stepId) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
      }),
    })}
  `;
}
