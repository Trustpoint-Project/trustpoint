import {
  addComputeAssignment,
  addSetVarEntry,
  addWebhookCaptureRule,
  removeComputeAssignment,
  removeSetVarEntry,
  removeWebhookCaptureRule,
  replaceComputeAssignments,
  replaceSetVarEntries,
  replaceWebhookCaptureRules,
  updateComputeAssignment,
  updateSetVarEntry,
  updateWebhookCaptureRule,
} from '../document/operations/step_content.js';
import {
  readComputeAssignmentRows,
  readSetVarRows,
  readWebhookCaptureRows,
} from '../steps/structured_step_editor_state.js';
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

    if (action === 'save-all-webhook-capture-rules') {
      const stepId = readStepId(button, context);
      const section = button.closest('[data-structured-step-section="webhook-capture"]');
      applyResult(
        applyYamlMutation,
        replaceWebhookCaptureRules({
          yamlText,
          stepId,
          rows: readWebhookCaptureRows(section),
        }),
        `Saved capture rules on "${stepId}".`,
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

    if (action === 'save-all-compute-assignments') {
      const stepId = readStepId(button, context);
      const section = button.closest('[data-structured-step-section="compute-assignments"]');
      applyResult(
        applyYamlMutation,
        replaceComputeAssignments({
          yamlText,
          stepId,
          rows: readComputeAssignmentRows(section),
        }),
        `Saved compute assignments on "${stepId}".`,
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

    if (action === 'save-all-set-var-entries') {
      const stepId = readStepId(button, context);
      const section = button.closest('[data-structured-step-section="set-vars"]');
      applyResult(
        applyYamlMutation,
        replaceSetVarEntries({
          yamlText,
          stepId,
          rows: readSetVarRows(section),
        }),
        `Saved vars entries on "${stepId}".`,
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
