import { escapeHtml } from '../core/dom.js';
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
  renderConditionDsl,
  renderConditionOperatorButtons,
  renderExpressionDsl,
  renderFieldSpecificOptions,
} from './guide_dsl_sections.js';

export function renderStepGuide(context, catalog) {
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

  let dslSection = '';
  if (context.fieldKey) {
    dslSection = renderFieldSpecificOptions(catalog, context);
  } else if (context.stepType === 'logic') {
    dslSection = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Quick actions</div>
        <div class="d-flex flex-wrap gap-2">
          ${renderActionButton('add-logic-case', 'Add compare case')}
        </div>
      </div>

      <div class="mb-2">
        <div class="fw-semibold mb-1">Insert logic case</div>
        ${renderConditionOperatorButtons(catalog, 'logic-case')}
      </div>

      ${renderConditionDsl(catalog)}
    `;
  } else if (context.stepType === 'compute') {
    dslSection = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Quick actions</div>
        <div class="d-flex flex-wrap gap-2">
          ${renderActionButton('add-compute-assignment', 'Add assignment')}
        </div>
      </div>

      ${renderComputeDsl(catalog, { insertable: true })}
    `;
  } else if (context.stepType === 'webhook') {
    const captureHelp = presentFieldKeys.includes('capture')
      ? `
        <div class="mb-3">
          <div class="fw-semibold mb-1">Quick actions</div>
          <div class="d-flex flex-wrap gap-2">
            ${renderActionButton('add-webhook-capture-rule', 'Add capture rule')}
          </div>
        </div>
      `
      : `
        <div class="mb-3 text-muted">
          Add the optional <code>capture</code> field first to insert capture rules.
        </div>
      `;

    dslSection = `
      ${captureHelp}
      ${renderExpressionDsl(catalog, { insertableFunctions: true })}
    `;
  } else if (context.stepType === 'set' || context.stepType === 'email') {
    dslSection = renderExpressionDsl(catalog, { insertableFunctions: true });
  }

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Current step</div>
      <div><strong>${escapeHtml(context.stepId || '-')}</strong> &middot; ${escapeHtml(context.stepType || '(unset)')}</div>
      <div class="text-muted mt-1">
        ${escapeHtml(stepSpec?.description || 'Choose a step type to unlock step-specific guidance.')}
      </div>
    </div>

    ${showTypeOptions ? `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose step type</div>
        ${renderStepTypeActions(catalog?.steps || [], context.stepType || null, 'set-step-type')}
      </div>
    ` : ''}

    <div class="mb-3">
      <div class="fw-semibold mb-1">Actions</div>
      <div class="d-flex flex-wrap gap-2">
        ${renderActionButton(
          'set-workflow-start',
          context.currentStartStep === context.stepId ? 'Already workflow start' : 'Set as workflow start',
          ` data-step-id="${escapeHtml(context.stepId || '')}"${context.currentStartStep === context.stepId ? ' disabled' : ''}`,
        )}
        ${context.stepType && missingRequiredFields.length
          ? renderActionButton('add-missing-required-fields', 'Add missing required fields')
          : ''}
      </div>
    </div>

    ${context.stepType ? `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Add optional field</div>
        ${renderOptionalFieldActions(missingOptionalFields)}
      </div>
    ` : ''}

    ${contextSupportsVariableInsertion(context) ? `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Insert event variable</div>
        ${renderVariableButtons(eventButtons)}
      </div>

      <div class="mb-3">
        <div class="fw-semibold mb-1">Insert workflow var</div>
        ${renderVariableButtons(varsButtons)}
      </div>
    ` : ''}

    ${dslSection ? `
      <div class="mb-3">
        <div class="fw-semibold mb-2">Available options</div>
        ${dslSection}
      </div>
    ` : ''}

    ${context.stepType ? `
      <div class="mb-2">
        <div class="fw-semibold mb-1">Missing required fields</div>
        <div>${renderFieldChips(missingRequiredFields, context.fieldKey)}</div>
      </div>

      <div class="mb-2">
        <div class="fw-semibold mb-1">Required fields</div>
        <div>${renderFieldChips(requiredFields, context.fieldKey)}</div>
      </div>

      <div>
        <div class="fw-semibold mb-1">Optional fields</div>
        <div>${renderFieldChips(optionalFields, context.fieldKey)}</div>
      </div>
    ` : ''}
  `;
}