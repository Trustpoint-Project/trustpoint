import { escapeHtml, renderChips } from '../shared/dom.js';
import { APPROVAL_OUTCOME_PRESETS } from '../document/approval_outcome_presets.js';
import { parseApplyItems } from './guide_apply_shared.js';
import {
  renderComputeDsl,
  renderConditionDsl,
  renderExpressionDsl,
  renderFieldSpecificOptions,
} from './guide_dsl_sections.js';
import {
  buildVariableSuggestions,
  contextSupportsVariableInsertion,
  findStepSpec,
  findTriggerSpec,
  renderActionButton,
  renderFieldChips,
  renderOptionalFieldActions,
  renderScalarSetterButtons,
  renderStepIdActions,
  renderStepTypeActions,
  renderVariableButtons,
} from './guide_ui_helpers.js';
import {
  renderGuideButtonRow,
  renderGuideMeta,
  renderGuideNote,
  renderGuidePage,
} from './guide_layout.js';

function renderMiniBlock(title, body, description = '') {
  return `
    <div class="wf2-guide-mini-block">
      <div class="wf2-guide-mini-title">${escapeHtml(title)}</div>
      ${description ? `<div class="wf2-guide-mini-description">${escapeHtml(description)}</div>` : ''}
      <div class="wf2-guide-mini-body">${body}</div>
    </div>
  `;
}

function renderEmpty(message) {
  return `<div class="text-muted">${escapeHtml(message)}</div>`;
}

function renderChipList(items, { prefix = '', emptyLabel = 'None' } = {}) {
  if (!Array.isArray(items) || !items.length) {
    return `<span class="text-muted">${escapeHtml(emptyLabel)}</span>`;
  }

  return renderChips(items, (item) => `<span class="wf2-chip"><strong>${escapeHtml(`${prefix}${item}`)}</strong></span>`);
}

function renderSourceValueChips(sourceKind, selectedValues, entries) {
  if (!Array.isArray(selectedValues) || !selectedValues.length) {
    return renderEmpty('No filters saved.');
  }

  const labelById = new Map(
    (entries || []).map((entry) => [String(entry?.id), entry?.title || String(entry?.id)]),
  );

  return `
    <div class="wf2-guide-selection-list">
      ${selectedValues
        .map((value) => `
          <div class="wf2-guide-selection-chip">
            <span>${escapeHtml(labelById.get(String(value)) || String(value))}</span>
            ${renderActionButton(
              'remove-trigger-source-value',
              'Remove',
              ` data-trigger-source-kind="${escapeHtml(sourceKind)}" data-trigger-source-value="${escapeHtml(String(value))}"`,
            )}
          </div>
        `)
        .join('')}
    </div>
  `;
}

function renderSelectControl({
  selectAttr,
  action,
  actionLabel,
  actionAttrs = '',
  placeholder,
  options,
}) {
  return `
    <div class="wf2-guide-inline-field" data-wf2-scope="true">
      <select class="form-select form-select-sm" ${selectAttr}>
        <option value="">${escapeHtml(placeholder)}</option>
        ${options}
      </select>
      ${renderActionButton(action, actionLabel, actionAttrs)}
    </div>
  `;
}

function renderTriggerSelection(context, catalog) {
  const events = [...(catalog?.events || [])].sort((left, right) =>
    String(left?.title || left?.key || '').localeCompare(String(right?.title || right?.key || '')),
  );

  return renderSelectControl({
    selectAttr: 'data-wf2-trigger-select="true"',
    action: 'set-trigger-on',
    actionLabel: 'Apply',
    placeholder: 'Choose trigger',
    options: events
      .map((eventSpec) => `
        <option value="${escapeHtml(eventSpec.key || '')}"${context.triggerKey === eventSpec.key ? ' selected' : ''}>
          ${escapeHtml(eventSpec.title || eventSpec.key || '')}
        </option>
      `)
      .join(''),
  });
}

function renderSourceSelector({ title, singularTitle, sourceKind, entries, selectedValues }) {
  const options = [...(entries || [])]
    .sort((left, right) => String(left?.title || left?.id || '').localeCompare(String(right?.title || right?.id || '')))
    .map((entry) => `
      <option value="${escapeHtml(String(entry.id))}">
        ${escapeHtml(entry.title || String(entry.id))}
      </option>
    `)
    .join('');

  return renderMiniBlock(
    title,
    `
      ${renderSelectControl({
        selectAttr: `data-wf2-trigger-source-select="${escapeHtml(sourceKind)}"`,
        action: 'add-trigger-source-selected',
        actionLabel: 'Add',
        actionAttrs: ` data-trigger-source-kind="${escapeHtml(sourceKind)}"${options ? '' : ' disabled'}`,
        placeholder: `Add ${singularTitle.toLowerCase()}`,
        options,
      })}
      ${renderSourceValueChips(sourceKind, selectedValues, entries)}
    `,
  );
}

function describeTriggerReference(triggerSpec) {
  if (!triggerSpec) {
    return renderGuideNote('Pick a trigger first to see the event-specific description and variables.');
  }

  const variableChips = Array.isArray(triggerSpec.context_vars) && triggerSpec.context_vars.length
    ? renderChipList(
        triggerSpec.context_vars.map((item) => item.template || item.path || ''),
        { prefix: '', emptyLabel: 'No event variables.' },
      )
    : renderEmpty('No event variables documented for this trigger.');

  return `
    ${renderMiniBlock(
      'Trigger description',
      `<div>${escapeHtml(triggerSpec.description || 'No additional description available.')}</div>`,
    )}
    ${renderMiniBlock('Event values', variableChips)}
  `;
}

function buildInvalidModel(context) {
  return {
    title: 'Invalid YAML',
    description: 'Fix the syntax error first. The guide stays minimal until the document parses again.',
    current: `<div class="text-danger">${escapeHtml(context?.parseMessage || 'Invalid YAML')}</div>`,
    actions: renderEmpty('Resolve the YAML error in the editor.'),
    reference: renderEmpty('No reference while the document is invalid.'),
  };
}

function buildRootModel(catalog) {
  return {
    title: 'Workflow document',
    description: 'The guide stays small and only highlights the next meaningful area to edit.',
    current: renderGuideNote('Start with trigger, then steps, then flow. YAML remains the source of truth.', 'info'),
    actions: renderEmpty('Move the cursor into trigger, steps, or flow to unlock targeted actions.'),
    reference: renderExpressionDsl(catalog),
  };
}

function buildTriggerModel(context, catalog) {
  const triggerSpec = context.triggerKey ? findTriggerSpec(catalog, context.triggerKey) : null;
  const currentSources = context?.currentTriggerSources || {
    trustpoint: false,
    caIds: [],
    domainIds: [],
    deviceIds: [],
  };
  const triggerSources = catalog?.trigger_sources || {
    cas: [],
    domains: [],
    devices: [],
  };

  return {
    title: 'Trigger',
    description: 'One trigger, one compact source scope, no extra dashboards inside the drawer.',
    current: `
      ${renderGuideMeta([
        { label: 'Trigger', value: triggerSpec?.title || triggerSpec?.key || 'Not set' },
        { label: 'Scope', value: currentSources.trustpoint ? 'All sources' : 'Scoped sources' },
      ])}
      ${triggerSpec
        ? renderGuideNote(triggerSpec.description || 'This trigger has no extra description.')
        : renderGuideNote('No trigger selected yet.')}
    `,
    actions: `
      ${renderMiniBlock('Trigger', renderTriggerSelection(context, catalog))}
      ${renderMiniBlock(
        'Source scope',
        `
          <div class="wf2-guide-segmented">
            ${renderActionButton(
              'set-trigger-trustpoint',
              currentSources.trustpoint ? 'All sources active' : 'All sources',
              ` data-trigger-trustpoint="true" data-wf2-segment="${currentSources.trustpoint ? 'current' : 'idle'}"${currentSources.trustpoint ? ' disabled' : ''}`,
            )}
            ${renderActionButton(
              'set-trigger-trustpoint',
              currentSources.trustpoint ? 'Scoped sources' : 'Scoped sources active',
              ` data-trigger-trustpoint="false" data-wf2-segment="${currentSources.trustpoint ? 'idle' : 'current'}"${currentSources.trustpoint ? '' : ' disabled'}`,
            )}
          </div>
          ${renderGuideNote(
            currentSources.trustpoint
              ? 'Saved filters stay visible, but dispatch is currently using all sources.'
              : 'Only explicit CA, domain, or device filters are considered.',
          )}
        `,
      )}
      ${renderSourceSelector({
        title: 'Certificate authorities',
        singularTitle: 'certificate authority',
        sourceKind: 'ca_ids',
        entries: triggerSources.cas || [],
        selectedValues: currentSources.caIds || [],
      })}
      ${renderSourceSelector({
        title: 'Domains',
        singularTitle: 'domain',
        sourceKind: 'domain_ids',
        entries: triggerSources.domains || [],
        selectedValues: currentSources.domainIds || [],
      })}
      ${renderSourceSelector({
        title: 'Devices',
        singularTitle: 'device',
        sourceKind: 'device_ids',
        entries: triggerSources.devices || [],
        selectedValues: currentSources.deviceIds || [],
      })}
    `,
    reference: describeTriggerReference(triggerSpec),
  };
}

function buildApplyModel(context, catalog, yamlText) {
  const applyItems = parseApplyItems(yamlText);
  const currentRuleIndex =
    Array.isArray(context?.path) && typeof context.path[1] === 'number'
      ? context.path[1]
      : null;
  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);

  return {
    title: 'Apply rules',
    description: 'Keep the guide focused on scaffolding and reference. The YAML stays readable.',
    current: `
      ${renderGuideMeta([
        { label: 'Rules', value: String(applyItems.length) },
        { label: 'Current rule', value: currentRuleIndex == null ? 'None' : String(currentRuleIndex + 1) },
      ])}
      ${renderGuideNote('Apply rules run before the workflow starts.')}
    `,
    actions: `
      ${renderMiniBlock(
        'Add rule',
        renderGuideButtonRow(`
          ${renderActionButton('add-apply-rule', 'Compare', ' data-apply-operator="compare"')}
          ${renderActionButton('add-apply-rule', 'Exists', ' data-apply-operator="exists"')}
          ${renderActionButton('add-apply-rule', 'Not', ' data-apply-operator="not"')}
          ${renderActionButton('add-apply-rule', 'And', ' data-apply-operator="and"')}
          ${renderActionButton('add-apply-rule', 'Or', ' data-apply-operator="or"')}
        `),
      )}
      ${renderMiniBlock(
        'Insert event value',
        renderGuideButtonRow(renderVariableButtons(eventButtons)),
        'Insert at the current YAML cursor position.',
      )}
      ${renderMiniBlock(
        'Insert workflow var',
        renderGuideButtonRow(renderVariableButtons(varsButtons)),
        'Only current workflow vars are offered here.',
      )}
    `,
    reference: renderConditionDsl(catalog),
  };
}

function buildWorkflowStartModel(context) {
  return {
    title: 'Workflow start',
    description: 'Keep `workflow.start` pointed at a real step id.',
    current: `
      ${renderGuideMeta([
        { label: 'Current start', value: context.currentStartStep || 'Not set' },
      ])}
      ${renderGuideNote('Choose the first step that should receive control.')}
    `,
    actions: renderGuideButtonRow(
      renderStepIdActions(context.stepIds || [], context.currentStartStep || null, 'set-workflow-start'),
    ),
    reference: renderMiniBlock(
      'Known step ids',
      renderChipList(context.stepIds || [], { emptyLabel: 'No steps yet.' }),
    ),
  };
}

function buildStepsAreaModel(context, catalog) {
  return {
    title: 'Steps',
    description: 'Add step scaffolds quickly and keep the YAML tidy.',
    current: `
      ${renderGuideMeta([
        { label: 'Steps', value: String((context.stepIds || []).length) },
        { label: 'Workflow start', value: context.currentStartStep || 'Not set' },
      ])}
      ${renderMiniBlock(
        'Known step ids',
        renderChipList(context.stepIds || [], { emptyLabel: 'No steps in the workflow yet.' }),
      )}
    `,
    actions: renderMiniBlock(
      'Add step',
      renderGuideButtonRow(renderStepTypeActions(catalog?.steps || [], null, 'add-step-from-type')),
    ),
    reference: renderGuideNote('Add the scaffold here, then refine the step directly in YAML.'),
  };
}

function buildStepModel(context, catalog) {
  const stepSpec = context.stepType ? findStepSpec(catalog, context.stepType) : null;
  const commonFields = catalog?.meta?.common_step_fields || [];
  const specificFields = stepSpec?.fields || [];
  const allFields = [...commonFields, ...specificFields];
  const requiredFields = allFields.filter((field) => !!field.required);
  const optionalFields = allFields.filter((field) => !field.required);
  const presentFieldKeys = context.stepFieldKeys || [];
  const missingRequiredFields = requiredFields.filter((field) => !presentFieldKeys.includes(field.key));
  const missingOptionalFields = optionalFields.filter((field) => !presentFieldKeys.includes(field.key));
  const { eventButtons, varsButtons } = buildVariableSuggestions(context, catalog);

  const currentParts = [
    renderGuideMeta([
      { label: 'Step', value: context.stepId || 'Unknown' },
      { label: 'Type', value: context.stepType || 'Not set' },
      { label: 'Field', value: context.fieldKey || 'step root' },
    ]),
  ];

  if (presentFieldKeys.length) {
    currentParts.push(
      renderMiniBlock('Fields present', renderFieldChips(allFields.filter((field) => presentFieldKeys.includes(field.key)), context.fieldKey)),
    );
  }

  if (context.availableVarNames?.length || context.producedVarNames?.length) {
    currentParts.push(
      renderMiniBlock('Workflow vars available', renderChipList(context.availableVarNames || [], { prefix: 'vars.', emptyLabel: 'None guaranteed here yet.' })),
    );
    currentParts.push(
      renderMiniBlock('Workflow vars written', renderChipList(context.producedVarNames || [], { prefix: 'vars.', emptyLabel: 'This step does not write vars.' })),
    );
  }

  const actionParts = [
    renderMiniBlock(
      'Primary actions',
      renderGuideButtonRow(`
        ${renderActionButton(
          'set-workflow-start',
          context.currentStartStep === context.stepId ? 'Already workflow start' : 'Set as workflow start',
          ` data-step-id="${escapeHtml(context.stepId || '')}"${context.currentStartStep === context.stepId ? ' disabled' : ''}`,
        )}
        ${context.stepType && missingRequiredFields.length
          ? renderActionButton('add-missing-required-fields', 'Add missing required fields')
          : ''}
      `),
    ),
  ];

  if (!context.stepType) {
    actionParts.unshift(
      renderMiniBlock('Step type', renderGuideButtonRow(renderStepTypeActions(catalog?.steps || [], null, 'set-step-type'))),
    );
  } else {
    actionParts.unshift(
      renderMiniBlock(
        'Add another step',
        renderGuideButtonRow(renderStepTypeActions(catalog?.steps || [], null, 'add-step-from-type')),
      ),
    );
  }

  if (context.stepType) {
    actionParts.push(
      renderMiniBlock('Optional fields', renderOptionalFieldActions(missingOptionalFields)),
    );
  }

  if (context.stepType === 'approval') {
    actionParts.push(
      renderMiniBlock(
        'Approval outcomes',
        renderGuideButtonRow(
          APPROVAL_OUTCOME_PRESETS
            .map((preset) =>
              renderActionButton(
                'apply-approval-outcome-preset',
                preset.label,
                ` data-approved-outcome="${escapeHtml(preset.approved)}" data-rejected-outcome="${escapeHtml(preset.rejected)}"`,
              ),
            )
            .join(''),
        ),
      ),
    );
    actionParts.push(
      renderMiniBlock(
        'Approval routing',
        renderGuideButtonRow(
          APPROVAL_OUTCOME_PRESETS
            .map((preset) =>
              renderActionButton(
                'apply-approval-terminal-routing-preset',
                `${preset.label} -> $end / $reject`,
                ` data-approved-outcome="${escapeHtml(preset.approved)}" data-rejected-outcome="${escapeHtml(preset.rejected)}" data-approved-target="${escapeHtml(preset.approvedTarget || '$end')}" data-rejected-target="${escapeHtml(preset.rejectedTarget || '$reject')}"`,
              ),
            )
            .join(''),
        ),
      ),
    );
  }

  if (contextSupportsVariableInsertion(context)) {
    actionParts.push(
      renderMiniBlock('Insert event value', renderGuideButtonRow(renderVariableButtons(eventButtons))),
    );
    actionParts.push(
      renderMiniBlock('Insert workflow var', renderGuideButtonRow(renderVariableButtons(varsButtons))),
    );
  }

  const referenceParts = [];
  const fieldSpecificOptions = context.fieldKey ? renderFieldSpecificOptions(catalog, context) : '';

  if (fieldSpecificOptions) {
    referenceParts.push(renderMiniBlock('Field options', fieldSpecificOptions));
  }

  if (context.stepType === 'logic') {
    referenceParts.push(renderMiniBlock('Condition reference', renderConditionDsl(catalog)));
  } else if (context.stepType === 'compute') {
    referenceParts.push(renderMiniBlock('Compute reference', renderComputeDsl(catalog, { insertable: true })));
  } else if (['webhook', 'set', 'email'].includes(context.stepType || '')) {
    referenceParts.push(renderMiniBlock('Expression reference', renderExpressionDsl(catalog, { insertableFunctions: true })));
  }

  if (!referenceParts.length && stepSpec?.description) {
    referenceParts.push(renderGuideNote(stepSpec.description));
  }

  if (context.stepType) {
    referenceParts.unshift(
      renderGuideNote('Step type changes are locked in the guide. Edit the YAML directly if you need to convert this step.'),
    );
  }

  return {
    title: context.stepId || 'Step',
    description: 'Keep the drawer narrow: summary, direct actions, and only the reference that helps right now.',
    current: currentParts.join(''),
    actions: actionParts.join(''),
    reference: referenceParts.join(''),
  };
}

function buildFlowModel(context, catalog) {
  const stepIds = Array.isArray(context?.stepIds) ? context.stepIds : [];
  const toOptions = [...stepIds, ...(catalog?.meta?.end_targets || [])];
  const currentFlowFrom = context?.currentFlowItem?.from || null;
  const currentFlowTo = context?.currentFlowItem?.to || null;
  const currentFlowOn = context?.currentFlowItem?.on || null;

  let fieldOptions = '';
  if (context.flowFieldKey === 'from') {
    fieldOptions = renderMiniBlock('Set from', renderGuideButtonRow(renderScalarSetterButtons(stepIds)));
  } else if (context.flowFieldKey === 'to') {
    fieldOptions = renderMiniBlock('Set target', renderGuideButtonRow(renderScalarSetterButtons(toOptions)));
  } else if (context.flowFieldKey === 'on') {
    fieldOptions = renderMiniBlock(
      'Set outcome',
      renderGuideButtonRow(renderScalarSetterButtons(context.currentFlowOutcomeOptions || [])),
    );
  }

  return {
    title: 'Flow',
    description: 'Keep edge editing direct and compact.',
    current: `
      ${renderGuideMeta([
        { label: 'From', value: currentFlowFrom || '-' },
        { label: 'On', value: currentFlowOn || '-' },
        { label: 'To', value: currentFlowTo || '-' },
      ])}
      ${renderGuideNote('Use quick edge actions for the common cases, then fine-tune the YAML if needed.')}
    `,
    actions: `
      ${renderMiniBlock(
        'Add edge',
        renderGuideButtonRow(`
          ${renderActionButton('add-flow-linear-edge', 'Linear edge')}
          ${renderActionButton('add-flow-outcome-edge', 'Outcome edge')}
        `),
      )}
      ${fieldOptions}
    `,
    reference: `
      ${renderMiniBlock('Step ids', renderChipList(stepIds, { emptyLabel: 'No steps yet.' }))}
      ${renderMiniBlock('Known outcomes', renderChipList(context.currentFlowOutcomeOptions || [], { emptyLabel: 'No outcomes available here.' }))}
      ${renderMiniBlock('End targets', renderChipList(catalog?.meta?.end_targets || [], { emptyLabel: 'No end targets documented.' }))}
    `,
  };
}

function resolveGuideModel(context, catalog, yamlText) {
  if (!context?.ok) {
    return buildInvalidModel(context);
  }

  switch (context.area) {
    case 'root':
      return buildRootModel(catalog);
    case 'trigger':
    case 'trigger.on':
    case 'trigger.sources':
      return buildTriggerModel(context, catalog);
    case 'apply':
    case 'apply.item':
      return buildApplyModel(context, catalog, yamlText);
    case 'workflow.start':
      return buildWorkflowStartModel(context);
    case 'workflow.steps':
      return buildStepsAreaModel(context, catalog);
    case 'workflow.steps.item':
    case 'workflow.steps.field':
      return buildStepModel(context, catalog);
    case 'workflow.flow':
    case 'workflow.flow.item':
      return buildFlowModel(context, catalog);
    default:
      return {
        title: context.title || 'Workflow document',
        description: 'This part of the YAML does not need extra guide chrome.',
        current: renderGuideNote(`Cursor is inside ${context.pathLabel || '(root)'}.`),
        actions: renderEmpty('Move into trigger, steps, apply, or flow for direct helpers.'),
        reference: renderEmpty('No extra reference for this section.'),
      };
  }
}

export function renderGuideContent(context, catalog, yamlText = '') {
  const model = resolveGuideModel(context, catalog, yamlText);

  return renderGuidePage({
    title: model.title,
    description: model.description,
    pathLabel: context?.pathLabel || '(root)',
    current: model.current,
    actions: model.actions,
    reference: model.reference,
  });
}
