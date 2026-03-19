import { escapeHtml } from '../core/dom.js';
import {
  renderApplyGuide,
  renderRootGuide,
  renderStepsAreaGuide,
  renderTriggerGuide,
  renderWorkflowStartGuide,
} from './guide_document_sections.js';
import { renderStepGuide } from './guide_step_sections.js';
import { renderFlowGuide } from './guide_flow_sections.js';

export function renderGuideContent(context, catalog) {
  if (!context?.ok) {
    return `
      <div class="fw-semibold mb-1">Invalid YAML</div>
      <div class="text-danger">${escapeHtml(context?.parseMessage || 'Invalid YAML')}</div>
    `;
  }

  switch (context.area) {
    case 'root':
      return renderRootGuide(catalog);

    case 'trigger':
    case 'trigger.on':
    case 'trigger.sources':
      return renderTriggerGuide(context, catalog);

    case 'apply':
    case 'apply.item':
      return renderApplyGuide(context, catalog);

    case 'workflow.start':
      return renderWorkflowStartGuide(context);

    case 'workflow.steps':
      return renderStepsAreaGuide(context, catalog);

    case 'workflow.steps.item':
    case 'workflow.steps.field':
      return renderStepGuide(context, catalog);

    case 'workflow.flow':
    case 'workflow.flow.item':
      return renderFlowGuide(context, catalog);

    default:
      return `
        <div class="fw-semibold mb-1">${escapeHtml(context.title || 'Workflow document')}</div>
        <div class="text-muted">
          Cursor is inside <code>${escapeHtml(context.pathLabel || '(root)')}</code>.
        </div>
      `;
  }
}