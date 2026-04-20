import { escapeHtml } from '../shared/dom.js';
import { buildExpressionFunctionInsertion } from '../document/expression_insertions.js';

function findTriggerSpec(catalog, triggerKey) {
  return (catalog?.events || []).find((eventSpec) => eventSpec.key === triggerKey) || null;
}

function toTitleCase(value) {
  return String(value || '')
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function buildVariableGroups({ catalog, triggerKey, availableVarNames = [] }) {
  const triggerSpec = triggerKey ? findTriggerSpec(catalog, triggerKey) : null;

  return {
    eventButtons: (triggerSpec?.context_vars || []).map((item) => ({
      label: item.title || item.path,
      insertText: item.template || `\${${item.path}}`,
    })),
    workflowButtons: (availableVarNames || []).map((name) => ({
      label: `vars.${name}`,
      insertText: `\${vars.${name}}`,
    })),
  };
}

function buildExpressionGroups(catalog) {
  const functionGroups = catalog?.dsl?.expressions?.function_groups || [];

  return functionGroups
    .map((group) => ({
      title: `${toTitleCase(group.group)} functions`,
      buttons: (group.functions || []).map((fn) => ({
        label: `${fn.name}()`,
        insertText: buildExpressionFunctionInsertion(fn.name),
        title: fn.description || '',
      })),
    }))
    .filter((group) => group.buttons.length);
}

function renderButtonGroup({ title, buttons, actionAttribute, targetId }) {
  if (!Array.isArray(buttons) || !buttons.length) {
    return '';
  }

  return `
    <div class="wf2-inline-variable-group">
      <div class="wf2-inline-variable-group-title">${escapeHtml(title)}</div>
      <div class="wf2-inline-variable-group-buttons">
        ${buttons
          .map(
            (button) => `
              <button
                type="button"
                class="wf2-inline-variable-chip"
                ${actionAttribute}="insert-inline-runtime"
                data-inline-variable-target="${escapeHtml(targetId)}"
                data-insert-text="${escapeHtml(button.insertText)}"
                ${button.title ? `title="${escapeHtml(button.title)}"` : ''}
              >
                ${escapeHtml(button.label)}
              </button>
            `,
          )
          .join('')}
      </div>
    </div>
  `;
}

export function renderInlineVariablePicker({
  actionAttribute = 'data-graph-overlay-action',
  catalog,
  triggerKey,
  availableVarNames = [],
  targetId = 'value',
  includeExpressions = true,
  label = 'Insert runtime value',
}) {
  const { eventButtons, workflowButtons } = buildVariableGroups({
    catalog,
    triggerKey,
    availableVarNames,
  });
  const expressionGroups = includeExpressions ? buildExpressionGroups(catalog) : [];

  if (!eventButtons.length && !workflowButtons.length && !expressionGroups.length) {
    return '';
  }

  return `
    <details class="wf2-inline-variable-picker">
      <summary>${escapeHtml(label)}</summary>
      <div class="wf2-inline-variable-picker-body">
        ${renderButtonGroup({
          title: 'Event',
          buttons: eventButtons,
          actionAttribute,
          targetId,
        })}
        ${renderButtonGroup({
          title: 'Workflow',
          buttons: workflowButtons,
          actionAttribute,
          targetId,
        })}
        ${expressionGroups
          .map((group) =>
            renderButtonGroup({
              title: group.title,
              buttons: group.buttons,
              actionAttribute,
              targetId,
            }),
          )
          .join('')}
      </div>
    </details>
  `;
}

export function insertInlineVariableIntoScope(scopeEl, actionEl) {
  const targetId = String(actionEl?.getAttribute('data-inline-variable-target') || '').trim();
  const insertText = String(actionEl?.getAttribute('data-insert-text') || '');
  if (!scopeEl || !targetId || !insertText) {
    return false;
  }

  const targetInput = Array.from(scopeEl.querySelectorAll('[data-inline-variable-target]')).find(
    (el) => el.getAttribute('data-inline-variable-target') === targetId,
  );

  if (!targetInput || typeof targetInput.value !== 'string') {
    return false;
  }

  const currentValue = targetInput.value || '';
  const start = typeof targetInput.selectionStart === 'number'
    ? targetInput.selectionStart
    : currentValue.length;
  const end = typeof targetInput.selectionEnd === 'number'
    ? targetInput.selectionEnd
    : currentValue.length;

  targetInput.value = `${currentValue.slice(0, start)}${insertText}${currentValue.slice(end)}`;

  if (typeof targetInput.focus === 'function') {
    targetInput.focus();
  }

  if (typeof targetInput.setSelectionRange === 'function') {
    const caret = start + insertText.length;
    targetInput.setSelectionRange(caret, caret);
  }

  targetInput.dispatchEvent(new Event('input', { bubbles: true }));
  return true;
}
