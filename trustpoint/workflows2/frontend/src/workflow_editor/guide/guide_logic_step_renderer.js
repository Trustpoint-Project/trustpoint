import { escapeHtml } from '../shared/dom.js';
import { getStep, parseRoot } from '../document/yaml_document.js';
import { renderLogicStepEditor } from '../logic/logic_step_editor_renderer.js';
import { renderConditionDsl } from './guide_dsl_sections.js';
import {
  buildVariableSuggestions,
  renderVariableButtons,
} from './guide_ui_helpers.js';
import {
  renderGuideButtonRow,
  renderGuideMeta,
  renderGuideNote,
  renderGuideSection,
} from './guide_layout.js';

function readLogicStepData(yamlText, stepId) {
  if (!stepId) {
    return null;
  }

  try {
    return getStep(parseRoot(yamlText), stepId);
  } catch {
    return null;
  }
}

function renderVariableSection(title, buttons, description) {
  return renderGuideSection({
    title,
    description,
    body: renderGuideButtonRow(renderVariableButtons(buttons)),
  });
}

function renderVariableSummaryChips(varNames, { emptyLabel = 'None' } = {}) {
  if (!Array.isArray(varNames) || !varNames.length) {
    return `<span class="text-muted">${escapeHtml(emptyLabel)}</span>`;
  }

  return varNames
    .map((name) => `<span class="wf2-chip"><strong>${escapeHtml(`vars.${name}`)}</strong></span>`)
    .join('');
}

export function renderLogicStepGuide(context, catalog, yamlText = '') {
  const stepData = readLogicStepData(yamlText, context?.stepId);
  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);
  const casesCount = Array.isArray(stepData?.cases) ? stepData.cases.length : 0;

  return `
    ${renderGuideSection({
      title: 'Logic routing',
      description: 'Edit nested conditions here without hand-building YAML indentation.',
      tone: 'accent',
      body: `
        ${renderGuideMeta([
          { label: 'Step', value: context?.stepId || '-' },
          { label: 'Type', value: context?.stepType || '-' },
          { label: 'Cases', value: String(casesCount) },
          { label: 'Default', value: stepData?.default || 'unset' },
        ])}
        ${renderGuideNote('Use the structured editor below for nested and/or/not trees. YAML stays authoritative, but mutations are applied on parsed document state.', 'info')}
      `,
    })}

    ${renderGuideSection({
      title: 'Case editor',
      description: 'Cases evaluate top to bottom. Each case needs a condition tree and an outcome.',
      body: stepData
        ? renderLogicStepEditor({
            actionAttribute: 'data-wf2-action',
            availableVarNames: context.availableVarNames || [],
            catalog,
            stepData,
            stepId: context.stepId,
            triggerKey: context.triggerKey || null,
          })
        : '<div class="text-muted">Current logic step could not be loaded from YAML.</div>',
    })}

    ${renderGuideSection({
      title: 'Step summary',
      description: 'Compact runtime reference for this logic step.',
      body: `
        <div class="text-muted mb-3">Workflow vars shown here follow guaranteed incoming paths only.</div>

        <div class="mb-3">
          <div class="fw-semibold mb-1">Workflow vars available here</div>
          <div>${renderVariableSummaryChips(context.availableVarNames, { emptyLabel: 'No workflow vars are guaranteed here yet.' })}</div>
        </div>

        <div>
          <div class="fw-semibold mb-1">Workflow vars written by this step</div>
          <div>${renderVariableSummaryChips(context.producedVarNames, { emptyLabel: 'Logic steps do not write workflow vars directly.' })}</div>
        </div>
      `,
    })}

    ${renderVariableSection(
      'Insert event variable',
      eventButtons,
      'Insert a trigger variable at the current YAML cursor position.',
    )}

    ${renderVariableSection(
      'Insert available workflow var',
      varsButtons,
      'Only workflow vars guaranteed before this step are offered here.',
    )}

    ${renderGuideSection({
      title: 'Condition reference',
      description: 'Documented operators and compare tokens available in the DSL.',
      body: renderConditionDsl(catalog),
    })}
  `;
}
