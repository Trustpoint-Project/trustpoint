import { escapeHtml, renderChips } from '../shared/dom.js';

export function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

export function findTriggerSpec(catalog, triggerKey) {
  return (catalog?.events || []).find((evt) => evt.key === triggerKey) || null;
}

export function renderActionButton(action, label, extraAttrs = '') {
  return (
    `<button type="button" class="btn btn-sm btn-outline-primary" data-wf2-action="${escapeHtml(action)}"${extraAttrs}>` +
    `${escapeHtml(label)}` +
    `</button>`
  );
}

export function renderFieldChips(fields, currentFieldKey = null) {
  if (!Array.isArray(fields) || !fields.length) {
    return '<span class="text-muted">None</span>';
  }

  return fields
    .map((field) => {
      const isCurrent = currentFieldKey && field.key === currentFieldKey;
      return (
        `<span class="wf2-chip${isCurrent ? ' border-primary' : ''}">` +
        `<strong>${escapeHtml(field.title || field.key || '')}</strong>` +
        (isCurrent ? ' &middot; current' : '') +
        `</span>`
      );
    })
    .join('');
}

export function renderOptionalFieldActions(fields) {
  if (!Array.isArray(fields) || !fields.length) {
    return '<div class="text-success">All optional fields are already present.</div>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    fields
      .map((field) =>
        renderActionButton(
          'add-optional-field',
          `Add ${field.title || field.key}`,
          ` data-field-key="${escapeHtml(field.key)}"`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderStepTypeActions(steps, currentType = null, action = 'set-step-type') {
  if (!Array.isArray(steps) || !steps.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    steps
      .map((step) => {
        const isCurrent = currentType && step.type === currentType;
        return renderActionButton(
          action,
          step.title || step.type,
          ` data-step-type="${escapeHtml(step.type)}"${isCurrent ? ' disabled' : ''}`,
        );
      })
      .join('') +
    `</div>`
  );
}

export function renderStepIdActions(stepIds, currentStepId = null, action = 'set-workflow-start') {
  if (!Array.isArray(stepIds) || !stepIds.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    stepIds
      .map((stepId) =>
        renderActionButton(
          action,
          stepId,
          ` data-step-id="${escapeHtml(stepId)}"${currentStepId === stepId ? ' disabled' : ''}`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderVariableButtons(buttons) {
  if (!Array.isArray(buttons) || !buttons.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    buttons
      .map((btn) =>
        renderActionButton(
          'insert-variable',
          btn.label,
          ` data-insert-text="${escapeHtml(btn.insertText)}"`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderScalarSetterButtons(values, formatter = null) {
  if (!Array.isArray(values) || !values.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    values
      .map((value) =>
        renderActionButton(
          'set-current-scalar',
          String(value),
          ` data-scalar-value="${escapeHtml(formatter ? formatter(value) : String(value))}"`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function renderTriggerButtons(events, currentTriggerKey = null) {
  if (!Array.isArray(events) || !events.length) {
    return '<span class="text-muted">None</span>';
  }

  return (
    `<div class="d-flex flex-wrap gap-2">` +
    events
      .map((evt) =>
        renderActionButton(
          'set-current-scalar',
          evt.title || evt.key,
          ` data-scalar-value="${escapeHtml(evt.key)}"${currentTriggerKey === evt.key ? ' disabled' : ''}`,
        ),
      )
      .join('') +
    `</div>`
  );
}

export function buildVariableSuggestions(context, catalog) {
  const triggerSpec = context.triggerKey
    ? findTriggerSpec(catalog, context.triggerKey)
    : null;

  const eventButtons = (triggerSpec?.context_vars || []).map((item) => ({
    label: item.title || item.path,
    insertText: item.template || `\${${item.path}}`,
  }));

  const availableVarNames = Array.isArray(context.availableVarNames)
    ? context.availableVarNames
    : (context.knownVarNames || []);

  const varsButtons = availableVarNames.map((name) => ({
    label: `vars.${name}`,
    insertText: `\${vars.${name}}`,
  }));

  return {
    eventButtons,
    varsButtons,
  };
}

export function contextSupportsVariableInsertion(context) {
  if (!context?.ok) {
    return false;
  }

  return [
    'apply',
    'apply.item',
    'workflow.steps.item',
    'workflow.steps.field',
  ].includes(context.area);
}

export function renderEventList(events) {
  return renderChips(events, (evt) => {
    return (
      `<span class="wf2-chip">` +
      `<strong>${escapeHtml(evt.title || evt.key || '')}</strong>` +
      ` &middot; ${escapeHtml(evt.key || '')}` +
      `</span>`
    );
  });
}
