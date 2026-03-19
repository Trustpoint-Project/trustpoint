import {
  buildExpressionFunctionInsertion,
  insertComputeOperator,
  insertConditionOperator,
  setCurrentScalarValue,
} from '../features/operations/dsl.js';
import {
  insertComputeAssignment,
  insertLogicCase,
  insertWebhookCaptureRule,
} from '../features/operations/nested.js';
import { addMissingRequiredFields, addOptionalField } from '../features/operations/step_fields.js';
import { addStepFromType, setCurrentStepType } from '../features/operations/steps.js';
import { setWorkflowStart } from '../features/operations/workflow.js';

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

  function fail(message, level = 'error') {
    setStatus(message);
    addIssue(level, message);
  }

  function cursorOffset() {
    return editor.getCursorInfo().offset;
  }

  containerEl.addEventListener('click', (event) => {
    const button = event.target.closest('[data-wf2-action]');
    if (!button) {
      return;
    }

    const action = button.getAttribute('data-wf2-action');
    const catalog = getCatalog();
    const context = getContext();
    const yamlText = getYamlText();

    if (action === 'insert-variable') {
      const insertText = button.getAttribute('data-insert-text');
      if (!insertText) {
        fail('No variable text found.', 'warning');
        return;
      }

      editor.insertText(insertText);
      setStatus(`Inserted ${insertText}`);
      return;
    }

    if (action === 'insert-expression-function') {
      const functionName = button.getAttribute('data-function-name');
      if (!functionName) {
        fail('No function selected.', 'warning');
        return;
      }

      const insertText = buildExpressionFunctionInsertion(functionName);
      editor.insertText(insertText);
      setStatus(`Inserted ${insertText}`);
      return;
    }

    if (action === 'insert-condition-operator') {
      const conditionKey = button.getAttribute('data-condition-key');
      const mode = button.getAttribute('data-condition-mode') || 'mapping';

      if (!catalog || !conditionKey) {
        fail('No condition operator selected.', 'warning');
        return;
      }

      try {
        const nextYaml = insertConditionOperator({
          yamlText,
          cursorOffset: cursorOffset(),
          catalog,
          conditionKey,
          mode,
          context,
        });

        applyYamlMutation(nextYaml, `Inserted ${conditionKey} scaffold.`);
      } catch (err) {
        fail(`Failed to insert condition scaffold: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'insert-compute-operator') {
      const operatorName = button.getAttribute('data-compute-op');
      if (!operatorName) {
        fail('No compute operator selected.', 'warning');
        return;
      }

      try {
        const nextYaml = insertComputeOperator({
          yamlText,
          cursorOffset: cursorOffset(),
          operatorName,
          context,
        });

        applyYamlMutation(nextYaml, `Inserted compute operator "${operatorName}".`);
      } catch (err) {
        fail(`Failed to insert compute operator: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'add-logic-case') {
      try {
        const nextYaml = insertLogicCase({
          yamlText,
          cursorOffset: cursorOffset(),
          context,
        });

        applyYamlMutation(nextYaml, 'Inserted logic case.');
      } catch (err) {
        fail(`Failed to insert logic case: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'add-compute-assignment') {
      try {
        const nextYaml = insertComputeAssignment({
          yamlText,
          cursorOffset: cursorOffset(),
          context,
        });

        applyYamlMutation(nextYaml, 'Inserted compute assignment.');
      } catch (err) {
        fail(`Failed to insert compute assignment: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'add-webhook-capture-rule') {
      try {
        const nextYaml = insertWebhookCaptureRule({
          yamlText,
          cursorOffset: cursorOffset(),
          context,
        });

        applyYamlMutation(nextYaml, 'Inserted webhook capture rule.');
      } catch (err) {
        fail(`Failed to insert webhook capture rule: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'set-current-scalar') {
      const rawValue = button.getAttribute('data-scalar-value');
      if (rawValue == null) {
        fail('No scalar value selected.', 'warning');
        return;
      }

      try {
        const nextYaml = setCurrentScalarValue({
          yamlText,
          cursorOffset: cursorOffset(),
          rawValue,
        });

        applyYamlMutation(nextYaml, `Set value to ${rawValue}.`);
      } catch (err) {
        fail(`Failed to set value: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'set-workflow-start') {
      const stepId = button.getAttribute('data-step-id') || context?.stepId;
      if (!stepId) {
        fail('No step selected for workflow.start.', 'warning');
        return;
      }

      try {
        const result = setWorkflowStart({
          yamlText,
          stepId,
        });

        if (!result.changed) {
          setStatus(`Workflow start is already "${stepId}".`);
          return;
        }

        applyYamlMutation(result.yamlText, `Set workflow.start to "${stepId}".`);
      } catch (err) {
        fail(`Failed to set workflow.start: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'add-step-from-type') {
      const stepType = button.getAttribute('data-step-type');
      if (!catalog || !stepType) {
        fail('No step type selected.', 'warning');
        return;
      }

      try {
        const result = addStepFromType({
          yamlText,
          catalog,
          stepType,
          cursorOffset: cursorOffset(),
        });

        applyYamlMutation(
          result.yamlText,
          `Added new ${stepType} step "${result.stepId}".`,
          {
            preserveScroll: false,
            searchText: `${result.stepId}:`,
            searchOffset: 0,
          },
        );
      } catch (err) {
        fail(`Failed to add step: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'set-step-type') {
      const stepType = button.getAttribute('data-step-type');
      if (!catalog || !context?.stepId || !stepType) {
        fail('No current step or step type selected.', 'warning');
        return;
      }

      try {
        const result = setCurrentStepType({
          yamlText,
          catalog,
          stepId: context.stepId,
          stepType,
        });

        if (!result.changed) {
          setStatus(`Step "${context.stepId}" already uses type "${stepType}".`);
          return;
        }

        applyYamlMutation(result.yamlText, `Set type of "${context.stepId}" to "${stepType}".`);
      } catch (err) {
        fail(`Failed to set step type: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (!catalog || !context?.stepId) {
      fail('No current step selected.', 'warning');
      return;
    }

    if (action === 'add-missing-required-fields') {
      try {
        const result = addMissingRequiredFields({
          yamlText,
          catalog,
          stepId: context.stepId,
        });

        if (!result.addedKeys.length) {
          setStatus('All required fields are already present.');
          return;
        }

        applyYamlMutation(
          result.yamlText,
          `Added required fields for step "${context.stepId}": ${result.addedKeys.join(', ')}`,
        );
      } catch (err) {
        fail(`Failed to add required fields: ${err instanceof Error ? err.message : String(err)}`);
      }
      return;
    }

    if (action === 'add-optional-field') {
      const fieldKey = button.getAttribute('data-field-key');
      if (!fieldKey) {
        fail('No optional field selected.', 'warning');
        return;
      }

      try {
        const result = addOptionalField({
          yamlText,
          catalog,
          stepId: context.stepId,
          fieldKey,
        });

        if (!result.addedKey) {
          setStatus(`Field "${fieldKey}" already exists.`);
          return;
        }

        applyYamlMutation(
          result.yamlText,
          `Added optional field "${result.addedKey}" to step "${context.stepId}".`,
        );
      } catch (err) {
        fail(`Failed to add optional field: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  });

  return {
    containerEl,
  };
}