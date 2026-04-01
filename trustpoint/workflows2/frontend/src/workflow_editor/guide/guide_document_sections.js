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
  renderGuideMeta,
  renderGuideSection,
} from './guide_layout.js';
import { renderTriggerSourcesGuide } from './guide_trigger_sources_renderer.js';

export function renderRootGuide(catalog) {
  return `
    ${renderGuideSection({
      title: 'Expressions',
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
        title: getCatalogUiText(catalog, 'guide_trigger_current_title', 'Trigger'),
        description: getCatalogUiText(
          catalog,
          'guide_trigger_browse_description',
          'Pick one documented trigger. Search by name, key, group, or description.',
        ),
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
          ) +
          renderTriggerCatalog(catalog?.events || [], context.triggerKey || null, catalog),
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
      title: 'Workflow start',
      description: '`workflow.start` must reference an existing step id.',
      body: renderGuideMeta([
        { label: 'Start', value: context.currentStartStep || 'None' },
      ]) + renderGuideButtonRow(
        renderStepIdActions(context.stepIds || [], context.currentStartStep || null, 'set-workflow-start'),
      ),
    })}
  `;
}

export function renderStepsAreaGuide(context, catalog) {
  return `
    ${renderGuideSection({
      title: 'Steps',
      description: 'Create a minimal step scaffold or jump off the current list of known step ids.',
      body: `
        <div class="mb-3">
          <div class="fw-semibold mb-1">Add new step</div>
          ${renderGuideButtonRow(renderStepTypeActions(catalog?.steps || [], null, 'add-step-from-type'))}
        </div>

        <div>
          <div class="fw-semibold mb-1">Known step ids</div>
          ${renderChips(context.stepIds || [], (stepId) => {
            return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
          })}
        </div>
      `,
    })}
  `;
}
