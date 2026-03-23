import { addMissingRequiredFields, addOptionalField } from '../document/operations/step_fields.js';
import { addStepFromType, setCurrentStepType } from '../document/operations/step_management.js';

export async function executeGuideStepAction(action, bag) {
  const { button, catalog, context, yamlText, cursorOffset, setStatus, applyYamlMutation, fail } = bag;

  try {
    if (action === 'add-step-from-type') {
      const stepType = button.getAttribute('data-step-type');
      if (!catalog || !stepType) {
        fail('No step type selected.', 'warning');
        return true;
      }

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
      return true;
    }

    if (action === 'set-step-type') {
      const stepType = button.getAttribute('data-step-type');
      if (!catalog || !context?.stepId || !stepType) {
        fail('No current step or step type selected.', 'warning');
        return true;
      }

      const result = setCurrentStepType({
        yamlText,
        catalog,
        stepId: context.stepId,
        stepType,
      });

      if (!result.changed) {
        setStatus(`Step "${context.stepId}" already uses type "${stepType}".`);
        return true;
      }

      applyYamlMutation(result.yamlText, `Set type of "${context.stepId}" to "${stepType}".`);
      return true;
    }

    if (action === 'add-missing-required-fields') {
      if (!catalog || !context?.stepId) {
        fail('No current step selected.', 'warning');
        return true;
      }

      const result = addMissingRequiredFields({
        yamlText,
        catalog,
        stepId: context.stepId,
      });

      if (!result.addedKeys.length) {
        setStatus('All required fields are already present.');
        return true;
      }

      applyYamlMutation(
        result.yamlText,
        `Added required fields for step "${context.stepId}": ${result.addedKeys.join(', ')}`,
      );
      return true;
    }

    if (action === 'add-optional-field') {
      const fieldKey = button.getAttribute('data-field-key');
      if (!catalog || !context?.stepId) {
        fail('No current step selected.', 'warning');
        return true;
      }
      if (!fieldKey) {
        fail('No optional field selected.', 'warning');
        return true;
      }

      const result = addOptionalField({
        yamlText,
        catalog,
        stepId: context.stepId,
        fieldKey,
      });

      if (!result.addedKey) {
        setStatus(`Field "${fieldKey}" already exists.`);
        return true;
      }

      applyYamlMutation(
        result.yamlText,
        `Added optional field "${result.addedKey}" to step "${context.stepId}".`,
      );
      return true;
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err), 'error');
    return true;
  }

  return false;
}
