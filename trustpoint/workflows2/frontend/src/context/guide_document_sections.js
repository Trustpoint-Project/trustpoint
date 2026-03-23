import { escapeHtml, renderChips } from '../core/dom.js';
import {
  findTriggerSpec,
  renderEventList,
  renderStepIdActions,
  renderStepTypeActions,
  renderTriggerButtons,
} from './guide_ui_helpers.js';
import { renderExpressionDsl } from './guide_dsl_sections.js';

export function renderRootGuide(catalog) {
  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">What you can do here</div>
      <div class="text-muted">
        Edit the YAML directly and use the guide to scaffold steps, fields, conditions, and expressions from the documented workflow language.
      </div>
    </div>

    ${renderExpressionDsl(catalog)}
  `;
}

export function renderTriggerGuide(context, catalog) {
  const triggerSpec = context.triggerKey
    ? findTriggerSpec(catalog, context.triggerKey)
    : null;

  if (context.area === 'trigger.on') {
    return `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Current trigger</div>
        <div>${triggerSpec ? escapeHtml(triggerSpec.title || triggerSpec.key) : '<span class="text-muted">None</span>'}</div>
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose trigger</div>
        ${renderTriggerButtons(catalog?.events || [], context.triggerKey || null)}
      </div>

      <div>
        <div class="fw-semibold mb-1">Available triggers</div>
        <div>${renderEventList(catalog?.events || [])}</div>
      </div>
    `;
  }

  if (context.area === 'trigger.sources') {
    return `
      <div class="fw-semibold mb-1">Source filters</div>
      <div class="text-muted">
        Configure whether this trigger applies trustpoint-wide, or only to selected CA IDs, domain IDs, or device IDs.
      </div>
    `;
  }

  return `
    <div class="text-muted">
      Configure how the workflow is triggered.
    </div>
  `;
}

export function renderWorkflowStartGuide(context) {
  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Current start step</div>
      <div>${context.currentStartStep ? escapeHtml(context.currentStartStep) : '<span class="text-muted">None</span>'}</div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Set workflow start</div>
      <div class="text-muted mb-2">
        <code>workflow.start</code> must reference an existing step id.
      </div>
      ${renderStepIdActions(context.stepIds || [], context.currentStartStep || null, 'set-workflow-start')}
    </div>
  `;
}

export function renderStepsAreaGuide(context, catalog) {
  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Add new step</div>
      <div class="text-muted mb-2">
        Create a new minimal step from the catalog scaffold at the cursor position.
      </div>
      ${renderStepTypeActions(catalog?.steps || [], null, 'add-step-from-type')}
    </div>

    <div>
      <div class="fw-semibold mb-1">Known step ids</div>
      <div>${renderChips(context.stepIds || [], (stepId) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
      })}</div>
    </div>
  `;
}