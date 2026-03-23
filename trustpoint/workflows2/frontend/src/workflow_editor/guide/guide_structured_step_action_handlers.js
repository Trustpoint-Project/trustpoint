import {
  addComputeAssignment,
  addSetVarEntry,
  addWebhookCaptureRule,
  removeComputeAssignment,
  removeSetVarEntry,
  removeWebhookCaptureRule,
  updateComputeAssignment,
  updateSetVarEntry,
  updateWebhookCaptureRule,
} from '../document/operations/step_content.js';
import { readValue } from './guide_action_helpers.js';

function readStepId(button, context) {
  return button.getAttribute('data-step-id') || context?.stepId || null;
}

function applyResult(applyYamlMutation, result, message) {
  applyYamlMutation(result.yamlText, message);
}

export async function executeGuideStructuredStepAction(action, bag) {
  const { button, context, yamlText, applyYamlMutation, fail } = bag;

  try {
    if (action === 'add-webhook-capture-rule') {
      const stepId = readStepId(button, context);
      applyResult(
        applyYamlMutation,
        addWebhookCaptureRule({ yamlText, stepId }),
        `Added capture rule to "${stepId}".`,
      );
      return true;
    }

    if (action === 'save-webhook-capture-rule') {
      const stepId = readStepId(button, context);
      const row = button.closest('[data-capture-row]');
      applyResult(
        applyYamlMutation,
        updateWebhookCaptureRule({
          yamlText,
          stepId,
          oldTarget: button.getAttribute('data-capture-target'),
          newTarget: readValue(row, '[data-capture-target-input="true"]'),
          source: readValue(row, '[data-capture-source-input="true"]'),
        }),
        `Updated capture rule on "${stepId}".`,
      );
      return true;
    }

    if (action === 'remove-webhook-capture-rule') {
      const stepId = readStepId(button, context);
      applyResult(
        applyYamlMutation,
        removeWebhookCaptureRule({
          yamlText,
          stepId,
          target: button.getAttribute('data-capture-target'),
        }),
        `Removed capture rule from "${stepId}".`,
      );
      return true;
    }

    if (action === 'add-compute-assignment') {
      const stepId = readStepId(button, context);
      applyResult(
        applyYamlMutation,
        addComputeAssignment({ yamlText, stepId }),
        `Added compute assignment to "${stepId}".`,
      );
      return true;
    }

    if (action === 'save-compute-assignment') {
      const stepId = readStepId(button, context);
      const row = button.closest('[data-compute-row]');
      applyResult(
        applyYamlMutation,
        updateComputeAssignment({
          yamlText,
          stepId,
          oldTarget: button.getAttribute('data-compute-target'),
          newTarget: readValue(row, '[data-compute-target-input="true"]'),
          operator: readValue(row, '[data-compute-operator-input="true"]'),
          argsText: readValue(row, '[data-compute-args-input="true"]'),
        }),
        `Updated compute assignment on "${stepId}".`,
      );
      return true;
    }

    if (action === 'remove-compute-assignment') {
      const stepId = readStepId(button, context);
      applyResult(
        applyYamlMutation,
        removeComputeAssignment({
          yamlText,
          stepId,
          target: button.getAttribute('data-compute-target'),
        }),
        `Removed compute assignment from "${stepId}".`,
      );
      return true;
    }

    if (action === 'add-set-var-entry') {
      const stepId = readStepId(button, context);
      applyResult(
        applyYamlMutation,
        addSetVarEntry({ yamlText, stepId }),
        `Added vars entry to "${stepId}".`,
      );
      return true;
    }

    if (action === 'save-set-var-entry') {
      const stepId = readStepId(button, context);
      const row = button.closest('[data-set-var-row]');
      applyResult(
        applyYamlMutation,
        updateSetVarEntry({
          yamlText,
          stepId,
          oldKey: button.getAttribute('data-set-var-key'),
          newKey: readValue(row, '[data-set-var-key-input="true"]'),
          value: readValue(row, '[data-set-var-value-input="true"]'),
        }),
        `Updated vars entry on "${stepId}".`,
      );
      return true;
    }

    if (action === 'remove-set-var-entry') {
      const stepId = readStepId(button, context);
      applyResult(
        applyYamlMutation,
        removeSetVarEntry({
          yamlText,
          stepId,
          key: button.getAttribute('data-set-var-key'),
        }),
        `Removed vars entry from "${stepId}".`,
      );
      return true;
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err), 'error');
    return true;
  }

  return false;
}
