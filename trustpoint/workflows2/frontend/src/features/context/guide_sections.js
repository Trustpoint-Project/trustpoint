import { escapeHtml, renderChips } from '../../core/dom.js';
import {
  buildVariableSuggestions,
  contextSupportsVariableInsertion,
  findStepSpec,
  findTriggerSpec,
  renderActionButton,
  renderEventList,
  renderFieldChips,
  renderOptionalFieldActions,
  renderScalarSetterButtons,
  renderStepIdActions,
  renderStepTypeActions,
  renderTriggerButtons,
  renderVariableButtons,
} from './helpers.js';
import {
  renderComputeDsl,
  renderConditionDsl,
  renderConditionOperatorButtons,
  renderExpressionDsl,
  renderFieldSpecificOptions,
} from './dsl_sections.js';

function renderRootGuide(catalog) {
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

function renderTriggerGuide(context, catalog) {
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

function renderApplyGuide(context, catalog) {
  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Suggestions</div>
      <div class="text-muted">
        Apply rules are evaluated before the workflow starts.
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Insert condition</div>
      ${renderConditionOperatorButtons(catalog, 'apply-item')}
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Insert event variable</div>
      ${renderVariableButtons(eventButtons)}
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Insert workflow var</div>
      ${renderVariableButtons(varsButtons)}
    </div>

    ${renderConditionDsl(catalog)}
  `;
}

function renderWorkflowStartGuide(context) {
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

function renderStepsAreaGuide(context, catalog) {
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

function renderStepGuide(context, catalog) {
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

function renderFlowGuide(context, catalog) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];
  const toOptions = [...stepIds, ...(catalog?.meta?.end_targets || [])];
  const currentFlowFrom = context?.currentFlowItem?.from || null;
  const currentFlowTo = context?.currentFlowItem?.to || null;
  const currentFlowOn = context?.currentFlowItem?.on || null;

  const outcomeStepSummaries = (context?.stepSummaries || []).filter(
    (item) => Array.isArray(item.outcomes) && item.outcomes.length > 0,
  );

  let fieldOptions = '';
  if (context.flowFieldKey === 'from') {
    fieldOptions = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose from-step</div>
        ${renderScalarSetterButtons(stepIds)}
      </div>
    `;
  } else if (context.flowFieldKey === 'to') {
    fieldOptions = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose target</div>
        ${renderScalarSetterButtons(toOptions)}
      </div>
    `;
  } else if (context.flowFieldKey === 'on') {
    fieldOptions = `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Choose outcome</div>
        ${renderScalarSetterButtons(context.currentFlowOutcomeOptions || [])}
      </div>
    `;
  }

  return `
    <div class="mb-3">
      <div class="fw-semibold mb-1">Quick actions</div>
      <div class="d-flex flex-wrap gap-2">
        ${renderActionButton('add-flow-linear-edge', 'Add linear edge')}
        ${renderActionButton('add-flow-outcome-edge', 'Add outcome edge')}
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Add linear edge from existing step</div>
      <div class="d-flex flex-wrap gap-2">
        ${
          stepIds.length
            ? stepIds
                .map((stepId) =>
                  renderActionButton(
                    'add-flow-linear-edge',
                    stepId,
                    ` data-flow-from="${escapeHtml(stepId)}"`,
                  ),
                )
                .join('')
            : '<span class="text-muted">No steps available</span>'
        }
      </div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Add outcome edge from existing step</div>
      <div class="d-flex flex-wrap gap-2">
        ${
          outcomeStepSummaries.length
            ? outcomeStepSummaries
                .map((item) =>
                  renderActionButton(
                    'add-flow-outcome-edge',
                    `${item.id} (${item.outcomes.join(', ')})`,
                    ` data-flow-from="${escapeHtml(item.id)}"`,
                  ),
                )
                .join('')
            : '<span class="text-muted">No outcome-producing steps available</span>'
        }
      </div>
    </div>

    ${
      currentFlowFrom || currentFlowTo || currentFlowOn
        ? `
      <div class="mb-3">
        <div class="fw-semibold mb-1">Current edge</div>
        <div class="text-muted">
          from: <code>${escapeHtml(currentFlowFrom || '-')}</code>,
          on: <code>${escapeHtml(currentFlowOn || '-')}</code>,
          to: <code>${escapeHtml(currentFlowTo || '-')}</code>
        </div>
      </div>
    `
        : ''
    }

    ${fieldOptions}

    <div class="mb-3">
      <div class="fw-semibold mb-1">Known step ids</div>
      <div>${renderChips(stepIds, (stepId) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(stepId)}</strong></span>`;
      })}</div>
    </div>

    <div class="mb-3">
      <div class="fw-semibold mb-1">Known outcomes</div>
      <div>${renderChips(context.currentFlowOutcomeOptions || [], (outcome) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(outcome)}</strong></span>`;
      })}</div>
    </div>

    <div>
      <div class="fw-semibold mb-1">End targets</div>
      <div>${renderChips(catalog?.meta?.end_targets || [], (target) => {
        return `<span class="wf2-chip"><strong>${escapeHtml(target)}</strong></span>`;
      })}</div>
    </div>
  `;
}

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