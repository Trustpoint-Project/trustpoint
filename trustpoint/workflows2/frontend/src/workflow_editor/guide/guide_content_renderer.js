import { escapeHtml } from '../shared/dom.js';
import {
  renderRootGuide,
  renderStepsAreaGuide,
  renderTriggerGuide,
  renderWorkflowStartGuide,
} from './guide_document_sections.js';
import { renderApplyGuide } from './guide_apply_sections.js';
import { renderStepGuide } from './guide_step_sections.js';
import { renderFlowGuide } from './guide_flow_sections.js';
import { renderGuidePage, renderGuideSection } from './guide_layout.js';

function describeContext(context) {
  switch (context?.area) {
    case 'trigger':
    case 'trigger.on':
    case 'trigger.sources':
      return 'Choose documented trigger options and source filters for this workflow.';
    case 'apply':
    case 'apply.item':
      return 'Apply rules run before the workflow starts and can filter execution early.';
    case 'workflow.start':
      return 'Pick which existing step should receive control first.';
    case 'workflow.steps':
      return 'Add steps from the catalog and keep the YAML graph-friendly while drafting.';
    case 'workflow.steps.item':
    case 'workflow.steps.field':
      return 'Edit this step using documented fields, outcomes, and structured helpers.';
    case 'workflow.flow':
    case 'workflow.flow.item':
      return 'Shape the draft flow graph without losing sync with YAML.';
    default:
      return 'Use the guide to insert documented workflow syntax while YAML stays the source of truth.';
  }
}

export function renderGuideContent(context, catalog, yamlText = '') {
  if (!context?.ok) {
    return renderGuidePage({
      title: 'Invalid YAML',
      description: 'Fix the syntax error first, then the guide can return to structured editing.',
      pathLabel: '(invalid)',
      body: renderGuideSection({
        title: 'Syntax error',
        tone: 'danger',
        body: `<div class="text-danger">${escapeHtml(context?.parseMessage || 'Invalid YAML')}</div>`,
      }),
    });
  }

  let body = '';
  switch (context.area) {
    case 'root':
      body = renderRootGuide(catalog);
      break;

    case 'trigger':
    case 'trigger.on':
    case 'trigger.sources':
      body = renderTriggerGuide(context, catalog);
      break;

    case 'apply':
    case 'apply.item':
      body = renderApplyGuide(context, catalog, yamlText);
      break;

    case 'workflow.start':
      body = renderWorkflowStartGuide(context);
      break;

    case 'workflow.steps':
      body = renderStepsAreaGuide(context, catalog);
      break;

    case 'workflow.steps.item':
    case 'workflow.steps.field':
      body = renderStepGuide(context, catalog, yamlText);
      break;

    case 'workflow.flow':
    case 'workflow.flow.item':
      body = renderFlowGuide(context, catalog);
      break;

    default:
      body = renderGuideSection({
        title: context.title || 'Workflow document',
        description: 'Cursor-aware hints update as you move through the YAML.',
        body: `
          <div class="text-muted">
            Cursor is inside <code>${escapeHtml(context.pathLabel || '(root)')}</code>.
          </div>
        `,
      });
  }

  return renderGuidePage({
    title: context.title || 'Workflow document',
    description: describeContext(context),
    pathLabel: context.pathLabel || '(root)',
    body,
  });
}
