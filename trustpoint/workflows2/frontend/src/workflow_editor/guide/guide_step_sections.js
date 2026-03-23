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
import {
  renderGuideButtonRow,
  renderGuideMeta,
  renderGuideSection,
} from './guide_layout.js';
import { renderLogicStepGuide } from './guide_logic_step_renderer.js';
import { renderStructuredStepEditor } from '../steps/structured_step_editor_renderer.js';
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

function renderFieldReferenceSection(requiredFields, optionalFields, missingRequiredFields, currentFieldKey) {
  return renderGuideSection({
    title: 'Field reference',
    description: 'Required and optional fields for the current step type.',
    body: `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Missing required fields</div>
        <div>${renderFieldChips(missingRequiredFields, currentFieldKey)}</div>
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-1">Required fields</div>
        <div>${renderFieldChips(requiredFields, currentFieldKey)}</div>
      </div>

      <div>
        <div class="fw-semibold mb-1">Optional fields</div>
        <div>${renderFieldChips(optionalFields, currentFieldKey)}</div>
      </div>
    `,
  });
}

function renderVariableSummaryChips(varNames, { prefix = 'vars.', emptyLabel = 'None' } = {}) {
  if (!Array.isArray(varNames) || !varNames.length) {
    return `<span class="text-muted">${escapeHtml(emptyLabel)}</span>`;
  }

  return varNames
    .map((name) => `<span class="wf2-chip"><strong>${escapeHtml(`${prefix}${name}`)}</strong></span>`)
    .join('');
}

function renderVariableScopeSection(context) {
  return renderGuideSection({
    title: 'Variable scope',
    description: 'Only workflow vars guaranteed on every incoming reachable path are considered available here.',
    body: `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Available before this step</div>
        <div>${renderVariableSummaryChips(context.availableVarNames, { emptyLabel: 'No workflow vars are guaranteed here yet.' })}</div>
      </div>

      <div>
        <div class="fw-semibold mb-1">Written by this step</div>
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

  const configurationBody = `
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
  `;

  const stepSpecificSections =
    context.stepType === 'logic'
      ? renderLogicStepGuide(context, catalog, yamlText)
      : renderNonLogicStepSpecificSection(context, catalog, presentFieldKeys, yamlText);

  const variableSections =
    contextSupportsVariableInsertion(context) && context.stepType !== 'logic'
      ? `
        ${renderVariableScopeSection(context)}

        ${renderGuideSection({
          title: 'Insert event variable',
          description: 'Insert at the current YAML cursor position.',
          body: renderGuideButtonRow(renderVariableButtons(eventButtons)),
        })}

        ${renderGuideSection({
          title: 'Insert available workflow var',
          description: 'Only workflow vars guaranteed before this step are offered here.',
          body: renderGuideButtonRow(renderVariableButtons(varsButtons)),
        })}
      `
      : '';

  return `
    ${renderGuideSection({
      title: 'Current step',
      description: stepSpec?.description || 'Choose a step type to unlock step-specific guidance.',
      tone: 'accent',
      body: `
        ${renderGuideMeta([
          { label: 'Step id', value: context.stepId || '-' },
          { label: 'Type', value: context.stepType || '(unset)' },
          { label: 'Field', value: context.fieldKey || 'step root' },
        ])}
      `,
    })}

    ${renderGuideSection({
      title: 'Configuration',
      description: 'Use these actions to shape the current step without breaking YAML structure.',
      body: configurationBody,
    })}

    ${variableSections}

    ${stepSpecificSections}

    ${context.stepType
      ? renderFieldReferenceSection(
          requiredFields,
          optionalFields,
          missingRequiredFields,
          context.fieldKey,
        )
      : ''}
  `;
}
