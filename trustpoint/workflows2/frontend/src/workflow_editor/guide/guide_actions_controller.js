import { buildExpressionFunctionInsertion } from '../document/expression_insertions.js';
import { insertInlineVariableIntoScope } from '../variables/inline_variable_picker.js';
import { createGuideActionContext } from './guide_action_helpers.js';
import { executeGuideDocumentAction } from './guide_document_action_handlers.js';
import { executeGuideLogicAction } from './guide_logic_action_handlers.js';
import { executeGuideStructuredStepAction } from './guide_structured_step_action_handlers.js';
import { executeGuideStepAction } from './guide_step_action_handlers.js';

export function createGuideActionsController({
  containerEl,
  editor,
  getCatalog,
  getContext,
  getYamlText,
  setStatus,
  addIssue,
  applyYamlMutation,
}) {
  if (!containerEl) {
    return null;
  }

  containerEl.addEventListener('input', (event) => {
    const filterInput = event.target.closest(
      '[data-wf2-filter-input="true"], [data-wf2-source-filter-input="true"]',
    );
    if (!filterInput) {
      return;
    }

    const group = filterInput.closest('[data-wf2-filter-group="true"], [data-wf2-source-group="true"]');
    if (!group) {
      return;
    }

    const needle = String(filterInput.value || '').trim().toLowerCase();
    const entries = [...group.querySelectorAll('[data-wf2-entry="true"], [data-wf2-source-entry="true"]')];
    let visibleCount = 0;

    entries.forEach((entry) => {
      const haystack = String(entry.getAttribute('data-search-text') || '').toLowerCase();
      const isVisible = !needle || haystack.includes(needle);
      entry.hidden = !isVisible;
      if (isVisible) {
        visibleCount += 1;
      }
    });

    const sections = [...group.querySelectorAll('[data-wf2-filter-section="true"]')];
    sections.forEach((section) => {
      const sectionEntries = [...section.querySelectorAll('[data-wf2-entry="true"], [data-wf2-source-entry="true"]')];
      const sectionVisible = sectionEntries.some((entry) => !entry.hidden);
      section.hidden = !sectionVisible;
    });

    const emptyState = group.querySelector('[data-wf2-empty-state="true"], [data-wf2-source-empty-state="true"]');
    if (emptyState) {
      emptyState.hidden = visibleCount > 0;
    }
  });

  containerEl.addEventListener('click', async (event) => {
    const button = event.target.closest('[data-wf2-action]');
    if (!button) {
      return;
    }

    const action = button.getAttribute('data-wf2-action');
    const actionContext = createGuideActionContext({
      button,
      containerEl,
      editor,
      getCatalog,
      getContext,
      getYamlText,
      setStatus,
      addIssue,
      applyYamlMutation,
    });

    if (action === 'insert-variable') {
      const insertText = button.getAttribute('data-insert-text');
      if (!insertText) {
        actionContext.fail('No variable text found.', 'warning');
        return;
      }

      editor.insertText(insertText);
      setStatus(`Inserted ${insertText}`);
      return;
    }

    if (action === 'insert-expression-function') {
      const functionName = button.getAttribute('data-function-name');
      if (!functionName) {
        actionContext.fail('No function selected.', 'warning');
        return;
      }

      const insertText = buildExpressionFunctionInsertion(functionName);
      editor.insertText(insertText);
      setStatus(`Inserted ${insertText}`);
      return;
    }

    if (action === 'insert-inline-runtime') {
      insertInlineVariableIntoScope(
        button.closest('[data-inline-variable-scope="true"]') || containerEl,
        button,
      );
      setStatus('Inserted runtime snippet into the current field.');
      return;
    }

    if (action === 'apply-webhook-capture-source') {
      const row = button.closest('[data-capture-row]');
      const sourceInput = row?.querySelector('[data-capture-source-input="true"]');
      if (!sourceInput) {
        actionContext.fail('No capture source field found.', 'warning');
        return;
      }

      sourceInput.value = button.getAttribute('data-capture-source-value') || '';
      setStatus('Applied capture source suggestion.');
      return;
    }

    if (await executeGuideStructuredStepAction(action, actionContext)) {
      return;
    }

    if (await executeGuideLogicAction(action, actionContext)) {
      return;
    }

    if (await executeGuideDocumentAction(action, actionContext)) {
      return;
    }

    await executeGuideStepAction(action, actionContext);
  });

  return {
    containerEl,
  };
}
