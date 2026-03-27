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

export function getCatalogUiText(catalog, key, fallback) {
  return catalog?.meta?.i18n?.[key] || fallback;
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

function groupEvents(events) {
  const groups = new Map();

  (events || []).forEach((eventSpec) => {
    const groupKey = eventSpec?.group || 'other';
    const current = groups.get(groupKey) || {
      key: groupKey,
      title: eventSpec?.group_title || groupKey,
      events: [],
    };

    current.events.push(eventSpec);
    groups.set(groupKey, current);
  });

  return [...groups.values()].map((group) => ({
    ...group,
    events: [...group.events].sort((left, right) =>
      String(left?.title || left?.key || '').localeCompare(String(right?.title || right?.key || '')),
    ),
  }));
}

export function renderTriggerCatalog(events, currentTriggerKey = null, catalog = null) {
  if (!Array.isArray(events) || !events.length) {
    return `<span class="text-muted">${escapeHtml(getCatalogUiText(catalog, 'guide_trigger_empty', 'No documented triggers available.'))}</span>`;
  }

  const searchPlaceholder = getCatalogUiText(catalog, 'guide_trigger_search_placeholder', 'Search triggers');
  const noMatchesLabel = getCatalogUiText(catalog, 'guide_trigger_no_matches', 'No matching triggers.');
  const selectAction = getCatalogUiText(catalog, 'guide_trigger_select_action', 'Use this trigger');
  const selectedAction = getCatalogUiText(catalog, 'guide_trigger_selected_action', 'Selected');

  return `
    <div class="wf2-source-group" data-wf2-filter-group="true">
      <div class="wf2-source-toolbar">
        <input
          type="search"
          class="form-control form-control-sm"
          placeholder="${escapeHtml(searchPlaceholder)}"
          data-wf2-filter-input="true"
        />
      </div>

      <div class="wf2-source-list">
        ${groupEvents(events)
          .map((group) => {
            return `
              <div class="mb-3" data-wf2-filter-section="true">
                <div class="small text-uppercase text-muted fw-semibold mb-2">
                  ${escapeHtml(group.title || group.key)} · ${group.events.length}
                </div>

                ${group.events
                  .map((evt) => {
                    const isSelected = currentTriggerKey === evt.key;
                    const metaParts = [evt.key, evt.description].filter(Boolean);
                    return `
                      <div
                        class="wf2-source-entry${isSelected ? ' wf2-source-entry-selected' : ''}"
                        data-wf2-entry="true"
                        data-search-text="${escapeHtml(evt.search_text || '')}"
                      >
                        <div class="wf2-source-entry-copy">
                          <div class="wf2-source-entry-title">${escapeHtml(evt.title || evt.key || '')}</div>
                          <div class="wf2-source-entry-meta">${escapeHtml(metaParts.join(' · '))}</div>
                        </div>
                        <div class="wf2-source-entry-actions">
                          ${renderActionButton(
                            'set-current-scalar',
                            isSelected ? selectedAction : selectAction,
                            ` data-scalar-value="${escapeHtml(evt.key)}"${isSelected ? ' disabled' : ''}`,
                          )}
                        </div>
                      </div>
                    `;
                  })
                  .join('')}
              </div>
            `;
          })
          .join('')}
      </div>

      <div class="wf2-source-empty text-muted" data-wf2-empty-state="true" hidden>
        ${escapeHtml(noMatchesLabel)}
      </div>
    </div>
  `;
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
    const label = evt?.group_title
      ? `${evt.title || evt.key || ''} · ${evt.group_title}`
      : (evt.title || evt.key || '');
    return (
      `<span class="wf2-chip">` +
      `<strong>${escapeHtml(label)}</strong>` +
      ` &middot; ${escapeHtml(evt.key || '')}` +
      `</span>`
    );
  });
}
