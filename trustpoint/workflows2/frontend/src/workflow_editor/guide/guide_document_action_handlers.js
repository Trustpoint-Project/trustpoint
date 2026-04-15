import {
  addApplyChild,
  addApplyRule,
  removeApplyChild,
  removeApplyRule,
  saveApplyCompare,
  saveApplyExists,
  setApplyNodeOperator,
} from '../document/operations/apply_rules.js';
import {
  insertComputeAssignment,
  insertComputeOperator,
  insertConditionOperator,
  insertFlowLinearEdge,
  insertFlowOutcomeEdge,
  insertWebhookCaptureRule,
  setCurrentScalarValue,
} from '../document/operations/guide_insertions.js';
import {
  addTriggerSourceValue,
  removeTriggerSourceValue,
  setTriggerTrustpoint,
} from '../document/operations/trigger_sources.js';
import { addOutcomeFlowEdge } from '../document/operations/graph.js';
import { setStepFieldValue } from '../document/operations/step_fields.js';
import { setWorkflowStart } from '../document/operations/workflow.js';
import { readValue } from './guide_action_helpers.js';

export async function executeGuideDocumentAction(action, bag) {
  const { button, scope, catalog, context, yamlText, cursorOffset, setStatus, applyYamlMutation, fail } = bag;

  try {
    if (action === 'add-apply-rule') {
      const operator = button.getAttribute('data-apply-operator') || 'compare';
      applyYamlMutation(addApplyRule({ yamlText, operator }).yamlText, `Added apply rule (${operator}).`);
      return true;
    }

    if (action === 'remove-apply-rule') {
      applyYamlMutation(
        removeApplyRule({
          yamlText,
          ruleIndex: button.getAttribute('data-apply-rule-index'),
        }).yamlText,
        'Removed apply rule.',
      );
      return true;
    }

    if (action === 'set-apply-node-operator') {
      const operator = readValue(scope, '[data-apply-node-operator-input="true"]');
      applyYamlMutation(
        setApplyNodeOperator({
          yamlText,
          ruleIndex: button.getAttribute('data-apply-rule-index'),
          path: button.getAttribute('data-apply-node-path'),
          operator,
        }).yamlText,
        `Changed apply operator to "${operator}".`,
      );
      return true;
    }

    if (action === 'save-apply-exists') {
      applyYamlMutation(
        saveApplyExists({
          yamlText,
          ruleIndex: button.getAttribute('data-apply-rule-index'),
          path: button.getAttribute('data-apply-node-path'),
          value: readValue(scope, '[data-apply-exists-input="true"]'),
        }).yamlText,
        'Saved exists condition.',
      );
      return true;
    }

    if (action === 'save-apply-compare') {
      applyYamlMutation(
        saveApplyCompare({
          yamlText,
          ruleIndex: button.getAttribute('data-apply-rule-index'),
          path: button.getAttribute('data-apply-node-path'),
          left: readValue(scope, '[data-apply-compare-left-input="true"]'),
          op: readValue(scope, '[data-apply-compare-op-input="true"]'),
          right: readValue(scope, '[data-apply-compare-right-input="true"]'),
        }).yamlText,
        'Saved compare condition.',
      );
      return true;
    }

    if (action === 'add-apply-child') {
      const operator = readValue(scope, '[data-apply-child-operator-input="true"]') || 'compare';
      applyYamlMutation(
        addApplyChild({
          yamlText,
          ruleIndex: button.getAttribute('data-apply-rule-index'),
          path: button.getAttribute('data-apply-node-path'),
          operator,
        }).yamlText,
        `Added nested "${operator}" condition.`,
      );
      return true;
    }

    if (action === 'remove-apply-child') {
      applyYamlMutation(
        removeApplyChild({
          yamlText,
          ruleIndex: button.getAttribute('data-apply-rule-index'),
          path: button.getAttribute('data-apply-node-path'),
        }).yamlText,
        'Removed nested condition.',
      );
      return true;
    }

    if (action === 'insert-condition-operator') {
      const conditionKey = button.getAttribute('data-condition-key');
      const mode = button.getAttribute('data-condition-mode') || 'mapping';
      if (!catalog || !conditionKey) {
        fail('No condition operator selected.', 'warning');
        return true;
      }

      applyYamlMutation(
        insertConditionOperator({
          yamlText,
          cursorOffset: cursorOffset(),
          catalog,
          conditionKey,
          mode,
          context,
        }),
        `Inserted ${conditionKey} scaffold.`,
      );
      return true;
    }

    if (action === 'insert-compute-operator') {
      const operatorName = button.getAttribute('data-compute-op');
      if (!operatorName) {
        fail('No compute operator selected.', 'warning');
        return true;
      }

      applyYamlMutation(
        insertComputeOperator({
          yamlText,
          cursorOffset: cursorOffset(),
          operatorName,
          context,
        }),
        `Inserted compute operator "${operatorName}".`,
      );
      return true;
    }

    if (action === 'add-compute-assignment') {
      applyYamlMutation(
        insertComputeAssignment({
          yamlText,
          cursorOffset: cursorOffset(),
          context,
        }),
        'Inserted compute assignment.',
      );
      return true;
    }

    if (action === 'add-webhook-capture-rule') {
      applyYamlMutation(
        insertWebhookCaptureRule({
          yamlText,
          cursorOffset: cursorOffset(),
          context,
        }),
        'Inserted webhook capture rule.',
      );
      return true;
    }

    if (action === 'add-flow-linear-edge') {
      applyYamlMutation(
        insertFlowLinearEdge({
          yamlText,
          context,
          fromStep: button.getAttribute('data-flow-from'),
          toStep: button.getAttribute('data-flow-to'),
        }),
        'Inserted linear flow edge.',
      );
      return true;
    }

    if (action === 'add-flow-outcome-edge') {
      applyYamlMutation(
        insertFlowOutcomeEdge({
          yamlText,
          context,
          fromStep: button.getAttribute('data-flow-from'),
          toStep: button.getAttribute('data-flow-to'),
          outcome: button.getAttribute('data-flow-outcome'),
        }),
        'Inserted outcome flow edge.',
      );
      return true;
    }

    if (action === 'set-current-scalar') {
      const rawValue = button.getAttribute('data-scalar-value');
      if (rawValue == null) {
        fail('No scalar value selected.', 'warning');
        return true;
      }

      applyYamlMutation(
        setCurrentScalarValue({
          yamlText,
          cursorOffset: cursorOffset(),
          rawValue,
        }),
        `Set value to ${rawValue}.`,
      );
      return true;
    }

    if (action === 'apply-current-field-suggestion') {
      const encodedValue = button.getAttribute('data-suggestion-value');
      const rawValue = encodedValue == null ? null : decodeURIComponent(encodedValue);
      if (rawValue == null || !context?.stepId || !context?.fieldKey) {
        fail('No current step field selected for this suggestion.', 'warning');
        return true;
      }

      applyYamlMutation(
        setStepFieldValue({
          yamlText,
          catalog,
          stepId: context.stepId,
          fieldKey: context.fieldKey,
          rawValue,
        }).yamlText,
        `Applied suggestion for "${context.fieldKey}".`,
      );
      return true;
    }

    if (action === 'apply-approval-outcome-preset') {
      if (!catalog || !context?.stepId) {
        fail('No approval step selected.', 'warning');
        return true;
      }

      const approvedOutcome = button.getAttribute('data-approved-outcome') || 'approved';
      const rejectedOutcome = button.getAttribute('data-rejected-outcome') || 'rejected';

      let nextYaml = setStepFieldValue({
        yamlText,
        catalog,
        stepId: context.stepId,
        fieldKey: 'approved_outcome',
        rawValue: approvedOutcome,
      }).yamlText;

      nextYaml = setStepFieldValue({
        yamlText: nextYaml,
        catalog,
        stepId: context.stepId,
        fieldKey: 'rejected_outcome',
        rawValue: rejectedOutcome,
      }).yamlText;

      applyYamlMutation(nextYaml, `Applied approval outcome preset to "${context.stepId}".`);
      return true;
    }

    if (action === 'apply-approval-terminal-routing-preset') {
      if (!catalog || !context?.stepId) {
        fail('No approval step selected.', 'warning');
        return true;
      }

      const approvedOutcome = button.getAttribute('data-approved-outcome') || 'approved';
      const rejectedOutcome = button.getAttribute('data-rejected-outcome') || 'rejected';
      const approvedTarget = button.getAttribute('data-approved-target') || '$end';
      const rejectedTarget = button.getAttribute('data-rejected-target') || '$reject';

      let nextYaml = setStepFieldValue({
        yamlText,
        catalog,
        stepId: context.stepId,
        fieldKey: 'approved_outcome',
        rawValue: approvedOutcome,
      }).yamlText;

      nextYaml = setStepFieldValue({
        yamlText: nextYaml,
        catalog,
        stepId: context.stepId,
        fieldKey: 'rejected_outcome',
        rawValue: rejectedOutcome,
      }).yamlText;

      nextYaml = addOutcomeFlowEdge({
        yamlText: nextYaml,
        fromStep: context.stepId,
        toStep: approvedTarget,
        outcome: approvedOutcome,
      }).yamlText;

      nextYaml = addOutcomeFlowEdge({
        yamlText: nextYaml,
        fromStep: context.stepId,
        toStep: rejectedTarget,
        outcome: rejectedOutcome,
      }).yamlText;

      applyYamlMutation(
        nextYaml,
        `Applied approval routing preset to "${context.stepId}" (${approvedOutcome} → ${approvedTarget}, ${rejectedOutcome} → ${rejectedTarget}).`,
      );
      return true;
    }

    if (action === 'set-trigger-trustpoint') {
      const enabled = button.getAttribute('data-trigger-trustpoint') === 'true';
      const result = setTriggerTrustpoint({ yamlText, enabled });
      if (!result.changed) {
        setStatus(enabled ? 'Trigger is already trustpoint-wide.' : 'Trigger already uses explicit source filters.');
        return true;
      }

      applyYamlMutation(
        result.yamlText,
        enabled ? 'Trigger is now trustpoint-wide.' : 'Trigger now uses explicit source filters.',
      );
      return true;
    }

    if (action === 'add-trigger-source-value') {
      const sourceKind = button.getAttribute('data-trigger-source-kind');
      const rawValue = button.getAttribute('data-trigger-source-value');
      if (!sourceKind || rawValue == null) {
        fail('No trigger source selected.', 'warning');
        return true;
      }

      const result = addTriggerSourceValue({ yamlText, sourceKind, rawValue });
      if (!result.changed) {
        setStatus('That source filter is already present.');
        return true;
      }

      applyYamlMutation(result.yamlText, 'Added trigger source filter.');
      return true;
    }

    if (action === 'remove-trigger-source-value') {
      const sourceKind = button.getAttribute('data-trigger-source-kind');
      const rawValue = button.getAttribute('data-trigger-source-value');
      if (!sourceKind || rawValue == null) {
        fail('No trigger source selected.', 'warning');
        return true;
      }

      const result = removeTriggerSourceValue({ yamlText, sourceKind, rawValue });
      if (!result.changed) {
        setStatus('That source filter is already absent.');
        return true;
      }

      applyYamlMutation(result.yamlText, 'Removed trigger source filter.');
      return true;
    }

    if (action === 'set-workflow-start') {
      const stepId = button.getAttribute('data-step-id') || context?.stepId;
      if (!stepId) {
        fail('No step selected for workflow.start.', 'warning');
        return true;
      }

      const result = setWorkflowStart({ yamlText, stepId });
      if (!result.changed) {
        setStatus(`Workflow start is already "${stepId}".`);
        return true;
      }

      applyYamlMutation(result.yamlText, `Set workflow.start to "${stepId}".`);
      return true;
    }
  } catch (err) {
    fail(err instanceof Error ? err.message : String(err), 'error');
    return true;
  }

  return false;
}
