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
