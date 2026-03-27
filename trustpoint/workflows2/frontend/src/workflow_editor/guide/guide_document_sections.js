import { escapeHtml, renderChips } from '../shared/dom.js';
import {
  findTriggerSpec,
  getCatalogUiText,
  renderStepIdActions,
  renderStepTypeActions,
  renderTriggerCatalog,
} from './guide_ui_helpers.js';
import { renderExpressionDsl } from './guide_dsl_sections.js';
import {
  renderGuideButtonRow,
  renderGuideNote,
  renderGuideMeta,
  renderGuideSection,
} from './guide_layout.js';
import { renderTriggerSourcesGuide } from './guide_trigger_sources_renderer.js';

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

  if (context.area === 'trigger' || context.area === 'trigger.on') {
    return `
      ${renderGuideSection({
        title: getCatalogUiText(catalog, 'guide_trigger_current_title', 'Current trigger'),
        body:
          renderGuideMeta([
            {
              label: getCatalogUiText(catalog, 'guide_trigger_selected_label', 'Selected'),
              value: triggerSpec?.title || triggerSpec?.key || getCatalogUiText(catalog, 'guide_trigger_none', 'None'),
            },
            ...(triggerSpec?.group_title
              ? [
                  {
                    label: getCatalogUiText(catalog, 'guide_trigger_group_label', 'Group'),
                    value: triggerSpec.group_title,
                  },
                ]
              : []),
          ]) +
          renderGuideNote(
            triggerSpec?.description || getCatalogUiText(
              catalog,
              'guide_trigger_note',
              'Choose a documented trigger to unlock event-specific help.',
            ),
            'muted',
          ),
      })}

      ${renderGuideSection({
        title: getCatalogUiText(catalog, 'guide_trigger_browse_title', 'Browse triggers'),
        description: getCatalogUiText(
          catalog,
          'guide_trigger_browse_description',
          'Search documented triggers by name, key, group, or description.',
        ),
        body: renderTriggerCatalog(catalog?.events || [], context.triggerKey || null, catalog),
      })}
    `;
  }

  if (context.area === 'trigger.sources') {
    return renderTriggerSourcesGuide(context, catalog);
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
