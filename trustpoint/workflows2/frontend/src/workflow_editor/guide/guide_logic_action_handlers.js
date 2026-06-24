import { decodeConditionPath } from '../document/condition_tree.js';
import {
  addLogicConditionChild,
  removeLogicConditionNode,
  saveLogicCompareNode,
  saveLogicExistsNode,
  setLogicConditionNodeKind,
} from '../document/operations/logic_condition_tree.js';
import {
  addLogicCase,
  removeLogicCase,
  setLogicCaseOutcome,
  setLogicDefaultOutcome,
} from '../document/operations/step_content.js';
import { readValue } from './guide_action_helpers.js';

function readCaseIndex(button) {
  return Number.parseInt(button.getAttribute('data-case-index') || '-1', 10);
}

function readStepId(button, context) {
  return button.getAttribute('data-step-id') || context?.stepId || null;
}

function applyResult(applyYamlMutation, result, message) {
  applyYamlMutation(result.yamlText, message);
}

export async function executeGuideLogicAction(action, bag) {
  const { button, context, yamlText, applyYamlMutation, fail } = bag;

  try {
    if (action === 'add-logic-case') {
      const stepId = readStepId(button, context);
      if (!stepId) {
        fail('No logic step selected.', 'warning');
        return true;
      }

      applyResult(
        applyYamlMutation,
        addLogicCase({ yamlText, stepId }),
        `Added logic case to "${stepId}".`,
      );
      return true;
    }

    if (action === 'remove-logic-case') {
      const stepId = readStepId(button, context);
      const index = readCaseIndex(button);
      applyResult(
        applyYamlMutation,
        removeLogicCase({ yamlText, stepId, index }),
        `Removed logic case ${index + 1} from "${stepId}".`,
      );
      return true;
    }

    if (action === 'save-logic-case-outcome') {
      const stepId = readStepId(button, context);
      const index = readCaseIndex(button);
      const row = button.closest('[data-logic-case-row]');
      applyResult(
        applyYamlMutation,
        setLogicCaseOutcome({
          yamlText,
          stepId,
          index,
          outcome: readValue(row, '[data-logic-case-outcome-input="true"]'),
        }),
        `Updated outcome for logic case ${index + 1} on "${stepId}".`,
      );
      return true;
    }

    if (action === 'save-logic-default') {
      const stepId = readStepId(button, context);
      const scope =
        button.closest('[data-wf2-scope="true"]') ||
        button.parentElement ||
        button.ownerDocument;
      applyResult(
        applyYamlMutation,
        setLogicDefaultOutcome({
          yamlText,
          stepId,
          outcome: readValue(scope, '[data-logic-default-input="true"]'),
        }),
        `Updated default outcome for "${stepId}".`,
      );
      return true;
    }

    const path = decodeConditionPath(button.getAttribute('data-condition-path'));

    if (action === 'set-logic-condition-kind') {
      const nodeScope = button.closest('[data-condition-node-path]');
      applyResult(
        applyYamlMutation,
        setLogicConditionNodeKind({
          yamlText,
          stepId: readStepId(button, context),
          caseIndex: readCaseIndex(button),
          kind: readValue(nodeScope, '[data-condition-kind-select="true"]'),
          path,
        }),
        `Updated condition operator for case ${readCaseIndex(button) + 1}.`,
      );
      return true;
    }

    if (action === 'save-logic-compare-node') {
      const nodeScope = button.closest('[data-condition-node-path]');
      applyResult(
        applyYamlMutation,
        saveLogicCompareNode({
          yamlText,
          stepId: readStepId(button, context),
          caseIndex: readCaseIndex(button),
          left: readValue(nodeScope, '[data-logic-compare-left="true"]'),
          op: readValue(nodeScope, '[data-logic-compare-op="true"]'),
          path,
          right: readValue(nodeScope, '[data-logic-compare-right="true"]'),
        }),
        `Updated compare condition for case ${readCaseIndex(button) + 1}.`,
      );
      return true;
    }

    if (action === 'save-logic-exists-node') {
      const nodeScope = button.closest('[data-condition-node-path]');
      applyResult(
        applyYamlMutation,
        saveLogicExistsNode({
          yamlText,
          stepId: readStepId(button, context),
          caseIndex: readCaseIndex(button),
          path,
          value: readValue(nodeScope, '[data-logic-exists-value="true"]'),
        }),
        `Updated exists condition for case ${readCaseIndex(button) + 1}.`,
      );
      return true;
    }

    if (action === 'add-logic-condition-child') {
      applyResult(
        applyYamlMutation,
        addLogicConditionChild({
          yamlText,
          stepId: readStepId(button, context),
          caseIndex: readCaseIndex(button),
          path,
        }),
        `Added nested condition to case ${readCaseIndex(button) + 1}.`,
      );
      return true;
    }

    if (action === 'remove-logic-condition-node') {
      applyResult(
        applyYamlMutation,
        removeLogicConditionNode({
          yamlText,
          stepId: readStepId(button, context),
          caseIndex: readCaseIndex(button),
          path,
        }),
        `Removed nested condition from case ${readCaseIndex(button) + 1}.`,
      );
      return true;
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err), 'error');
    return true;
  }

  return false;
}
