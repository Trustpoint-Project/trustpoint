import { escapeHtml } from '../shared/dom.js';
import {
  buildVariableSuggestions,
  contextSupportsVariableInsertion,
  findStepSpec,
  renderActionButton,
  renderFieldChips,
  renderOptionalFieldActions,
  renderStepTypeActions,
  renderVariableButtons,
} from './guide_ui_helpers.js';
import {
  renderComputeDsl,
  renderExpressionDsl,
  renderFieldSpecificOptions,
} from './guide_dsl_sections.js';
import { renderGuideButtonRow, renderGuideMeta, renderGuideSection } from './guide_layout.js';
import { renderLogicStepGuide } from './guide_logic_step_renderer.js';
import { renderStructuredStepEditor } from '../steps/structured_step_editor_renderer.js';
import { APPROVAL_OUTCOME_PRESETS } from '../document/approval_outcome_presets.js';
import { getStep, parseRoot } from '../document/yaml_document.js';

function readCurrentStepData(yamlText, stepId) {
  if (!stepId) {
    return null;
  }

  try {
    return getStep(parseRoot(yamlText), stepId);
  } catch {
    return null;
  }
}

function renderVariableSummaryChips(varNames, { prefix = 'vars.', emptyLabel = 'None' } = {}) {
  if (!Array.isArray(varNames) || !varNames.length) {
    return `<span class="text-muted">${escapeHtml(emptyLabel)}</span>`;
  }

  return varNames
    .map((name) => `<span class="wf2-chip"><strong>${escapeHtml(`${prefix}${name}`)}</strong></span>`)
    .join('');
}

function renderStepSummarySection(context) {
  const reachability = context.availableVarNames?.length || context.producedVarNames?.length
    ? 'Workflow vars shown here follow guaranteed incoming paths only.'
    : 'No workflow vars are guaranteed here yet.';

  return renderGuideSection({
    title: 'Step summary',
    description: 'Compact runtime reference for the current step.',
    body: `
      <div class="text-muted mb-3">${escapeHtml(reachability)}</div>

      <div class="mb-3">
        <div class="fw-semibold mb-1">Workflow vars available here</div>
        <div>${renderVariableSummaryChips(context.availableVarNames, { emptyLabel: 'No workflow vars are guaranteed here yet.' })}</div>
      </div>

      <div>
        <div class="fw-semibold mb-1">Workflow vars written by this step</div>
        <div>${renderVariableSummaryChips(context.producedVarNames, { emptyLabel: 'This step does not define workflow vars.' })}</div>
      </div>
    `,
  });
}

function renderNonLogicStepSpecificSection(context, catalog, presentFieldKeys, yamlText = '') {
  const stepData = readCurrentStepData(yamlText, context.stepId);

  if (['webhook', 'compute', 'set'].includes(context.stepType || '')) {
    const specificFieldOptions = context.fieldKey
      ? renderFieldSpecificOptions(catalog, context)
      : '';
    const helperSections = [];

    if (specificFieldOptions) {
      helperSections.push(renderGuideSection({
        title: 'Field-specific options',
        description: `Documented choices for "${context.fieldKey}".`,
        body: specificFieldOptions,
      }));
    }

    if (context.stepType === 'webhook') {
      helperSections.push(renderGuideSection({
        title: 'Expression helpers',
        description: 'Insert documented functions and runtime references for request templates.',
        body: renderExpressionDsl(catalog, { insertableFunctions: true }),
      }));
    }

    if (context.stepType === 'compute') {
      helperSections.push(renderGuideSection({
        title: 'Compute reference',
        description: 'Supported compute operators and expression helpers.',
        body: renderComputeDsl(catalog, { insertable: true }),
      }));
    }

    if (context.stepType === 'set') {
      helperSections.push(renderGuideSection({
        title: 'Expression helpers',
        description: 'Insert documented functions and runtime references for set step values.',
        body: renderExpressionDsl(catalog, { insertableFunctions: true }),
      }));
    }

    return `
      ${renderGuideSection({
        title: 'Structured editor',
        description: 'Edit the managed step content directly without hand-editing nested YAML.',
        body: stepData
          ? renderStructuredStepEditor({
              actionAttribute: 'data-wf2-action',
              availableVarNames: context.availableVarNames || [],
              catalog,
              stepData,
              stepId: context.stepId,
              stepType: context.stepType,
              triggerKey: context.triggerKey || null,
            })
          : '<div class="text-muted">Current step could not be loaded from YAML.</div>',
      })}
      ${helperSections.join('')}
    `;
  }

  if (context.fieldKey) {
    const options = renderFieldSpecificOptions(catalog, context);
    if (!options) {
      return '';
    }

    return renderGuideSection({
      title: 'Field-specific options',
      description: `Documented choices for "${context.fieldKey}".`,
      body: options,
    });
  }

  if (context.stepType === 'compute') {
    return renderGuideSection({
      title: 'Compute helpers',
      description: 'Use documented operators for assignment-style compute steps.',
      body: `
        <div class="mb-3">
          <div class="fw-semibold mb-1">Quick actions</div>
          ${renderGuideButtonRow(renderActionButton('add-compute-assignment', 'Add assignment'))}
        </div>

        ${renderComputeDsl(catalog, { insertable: true })}
      `,
    });
  }

  if (context.stepType === 'webhook') {
    const captureHelp = presentFieldKeys.includes('capture')
      ? `
        <div class="mb-3">
          <div class="fw-semibold mb-1">Quick actions</div>
          ${renderGuideButtonRow(renderActionButton('add-webhook-capture-rule', 'Add capture rule'))}
        </div>
      `
      : `
        <div class="text-muted">
          Add the optional <code>capture</code> field first to insert capture rules.
        </div>
      `;

    return renderGuideSection({
      title: 'Webhook helpers',
      description: 'Manage capture mappings and expression helpers for webhook processing.',
      body: `
        ${captureHelp}
        ${renderExpressionDsl(catalog, { insertableFunctions: true })}
      `,
    });
  }

  if (context.stepType === 'set' || context.stepType === 'email') {
    return renderGuideSection({
      title: 'Expression helpers',
      description: 'Insert documented functions and runtime references.',
      body: renderExpressionDsl(catalog, { insertableFunctions: true }),
    });
  }

  if (context.stepType === 'approval') {
    return renderGuideSection({
      title: 'Approval outcome presets',
      description: 'Apply a common approved/rejected naming pair to the current approval step.',
      body: renderGuideButtonRow(
        APPROVAL_OUTCOME_PRESETS
          .map((preset) =>
            renderActionButton(
              'apply-approval-outcome-preset',
              preset.label,
              ` data-approved-outcome="${escapeHtml(preset.approved)}" data-rejected-outcome="${escapeHtml(preset.rejected)}" title="${escapeHtml(preset.description)}"`,
            ),
          )
          .join(''),
      ),
    });
  }

  return '';
}

export function renderStepGuide(context, catalog, yamlText = '') {
  const stepSpec = context.stepType ? findStepSpec(catalog, context.stepType) : null;
  const commonFields = catalog?.meta?.common_step_fields || [];
  const specificFields = stepSpec?.fields || [];
  const allFields = [...commonFields, ...specificFields];
  const requiredFields = allFields.filter((field) => !!field.required);
  const optionalFields = allFields.filter((field) => !field.required);

  const presentFieldKeys = context.stepFieldKeys || [];
  const missingRequiredFields = requiredFields.filter(
    (field) => !presentFieldKeys.includes(field.key),
  );
  const missingOptionalFields = optionalFields.filter(
    (field) => !presentFieldKeys.includes(field.key),
  );

  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);
  const showTypeOptions = context.fieldKey === 'type' || !context.stepType;

  const stepBody = `
    ${renderGuideMeta([
      { label: 'Step id', value: context.stepId || '-' },
      { label: 'Type', value: context.stepType || '(unset)' },
      { label: 'Field', value: context.fieldKey || 'step root' },
    ])}

    ${showTypeOptions ? `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose step type</div>
        ${renderGuideButtonRow(renderStepTypeActions(catalog?.steps || [], context.stepType || null, 'set-step-type'))}
      </div>
    ` : ''}

    <div class="mb-3">
      <div class="fw-semibold mb-1">Primary actions</div>
      ${renderGuideButtonRow(`
        ${renderActionButton(
          'set-workflow-start',
          context.currentStartStep === context.stepId ? 'Already workflow start' : 'Set as workflow start',
          ` data-step-id="${escapeHtml(context.stepId || '')}"${context.currentStartStep === context.stepId ? ' disabled' : ''}`,
        )}
        ${context.stepType && missingRequiredFields.length
          ? renderActionButton('add-missing-required-fields', 'Add missing required fields')
          : ''}
      `)}
    </div>

    ${context.stepType ? `
      <div>
        <div class="fw-semibold mb-1">Add optional field</div>
        ${renderOptionalFieldActions(missingOptionalFields)}
      </div>
    ` : ''}

    ${context.stepType ? `
      <div class="mt-3">
        <div class="fw-semibold mb-1">Fields in this step</div>
        <div class="mb-2">${renderFieldChips(requiredFields, context.fieldKey)}</div>
        <div>${renderFieldChips(optionalFields, context.fieldKey)}</div>
      </div>
    ` : ''}
  `;

  const stepSpecificSections =
    context.stepType === 'logic'
      ? renderLogicStepGuide(context, catalog, yamlText)
      : renderNonLogicStepSpecificSection(context, catalog, presentFieldKeys, yamlText);

  const variableSection =
    contextSupportsVariableInsertion(context) && context.stepType !== 'logic'
      ? renderGuideSection({
          title: 'Insert values',
          description: 'Insert event values or workflow vars at the current YAML cursor position.',
          body: `
            <div class="mb-3">
              <div class="fw-semibold mb-1">Event values</div>
              ${renderGuideButtonRow(renderVariableButtons(eventButtons))}
            </div>

            <div>
              <div class="fw-semibold mb-1">Workflow vars available here</div>
              ${renderGuideButtonRow(renderVariableButtons(varsButtons))}
            </div>
          `,
        })
      : '';

  return `
    ${renderGuideSection({
      title: 'Step',
      description: stepSpec?.description || 'Choose a step type to unlock step-specific guidance.',
      tone: 'accent',
      body: stepBody,
    })}

    ${variableSection}

    ${stepSpecificSections}

    ${context.stepType ? renderStepSummarySection(context) : ''}
  `;
}
