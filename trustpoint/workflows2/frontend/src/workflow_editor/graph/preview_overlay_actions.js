import { parseConditionPath, parseEdgeId, readInputValue } from './preview_helpers.js';
import { insertInlineVariableIntoScope } from '../variables/inline_variable_picker.js';
import {
  readComputeAssignmentRows,
  readSetVarRows,
  readWebhookCaptureRows,
} from '../steps/structured_step_editor_state.js';
import { readGraphStepEditorDraft } from './step_editor_draft.js';
import {
  clearCanvasMenu,
  clearEditor,
  clearSelection,
  openNodeEditor,
} from './preview_state_helpers.js';

export async function handleGraphAction({
  action,
  actionEl,
  scope,
  refs,
  state,
  callbacks,
  render,
}) {
  const path = parseConditionPath(actionEl.getAttribute('data-condition-path'));

  if (action === 'close-editor') {
    clearEditor(state);
    clearCanvasMenu(state);
    render();
    return;
  }

  if (action === 'close-canvas-menu') {
    clearCanvasMenu(state);
    render();
    return;
  }

  if (action === 'add-step') {
    const stepType = refs.addStepSelect.value;
    if (!stepType) {
      return;
    }

    const result = await callbacks.onAddStep(stepType);
    if (result?.stepId) {
      openNodeEditor(state, result.stepId);
    }
    return;
  }

  if (action === 'insert-inline-runtime') {
    insertInlineVariableIntoScope(
      actionEl.closest('[data-inline-variable-scope="true"]') || scope,
      actionEl,
    );
    return;
  }

  if (action === 'apply-step-field-suggestion') {
    const row = actionEl.closest('[data-step-field-row]');
    const input = row?.querySelector('[data-step-field-input="true"]');
    if (input) {
      input.value = decodeURIComponent(actionEl.getAttribute('data-suggestion-value') || '');
    }
    return;
  }

  if (action === 'apply-approval-outcome-preset') {
    const approvedRow = scope.querySelector('[data-step-field-row="approved_outcome"]');
    const rejectedRow = scope.querySelector('[data-step-field-row="rejected_outcome"]');
    const approvedInput = approvedRow?.querySelector('[data-step-field-input="true"]');
    const rejectedInput = rejectedRow?.querySelector('[data-step-field-input="true"]');

    if (approvedInput) {
      approvedInput.value = actionEl.getAttribute('data-approved-outcome') || '';
    }
    if (rejectedInput) {
      rejectedInput.value = actionEl.getAttribute('data-rejected-outcome') || '';
    }
    return;
  }

  if (action === 'apply-webhook-capture-source') {
    const row = actionEl.closest('[data-capture-row]');
    const sourceInput = row?.querySelector('[data-capture-source-input="true"]');
    if (sourceInput) {
      sourceInput.value = actionEl.getAttribute('data-capture-source-value') || '';
    }
    return;
  }

  if (action === 'context-add-step') {
    const stepType = actionEl.getAttribute('data-step-type');
    if (!stepType) {
      return;
    }

    const menuPos = state.canvasMenuPos;
    const result = await callbacks.onAddStep(stepType);

    if (result?.stepId && menuPos) {
      state.nodePositions[result.stepId] = {
        x: Math.max(40, menuPos.x - 95),
        y: Math.max(40, menuPos.y - 38),
      };
      openNodeEditor(state, result.stepId);
    }

    clearCanvasMenu(state);
    return;
  }

  if (action === 'save-node-title' || action === 'save-title') {
    const stepId = actionEl.getAttribute('data-step-id');
    const titleInput = scope.querySelector('[data-node-title-input="true"]');
    await callbacks.onSetTitle(stepId, titleInput?.value || '');
    return;
  }

  if (action === 'save-step-editor') {
    const stepId = actionEl.getAttribute('data-step-id');
    const stepType = actionEl.getAttribute('data-step-type') || '';
    const draft = readGraphStepEditorDraft(scope, stepType);
    await callbacks.onSaveStepEditor(stepId, stepType, draft);
    clearEditor(state);
    clearCanvasMenu(state);
    render();
    return;
  }

  if (action === 'save-step-field') {
    const stepId = actionEl.getAttribute('data-step-id');
    const fieldKey = actionEl.getAttribute('data-field-key');
    const row = actionEl.closest('[data-step-field-row]');
    await callbacks.onSaveStepField(stepId, fieldKey, readInputValue(row, '[data-step-field-input="true"]'));
    return;
  }

  if (action === 'save-step-field-section') {
    const stepId = actionEl.getAttribute('data-step-id');
    const section = actionEl.closest('[data-step-field-section="true"]');
    const updates = [...(section?.querySelectorAll('[data-step-field-row]') || [])].map((row) => ({
      fieldKey: row.getAttribute('data-step-field-row'),
      rawValue: readInputValue(row, '[data-step-field-input="true"]'),
    }));
    await callbacks.onSaveStepFields(stepId, updates);
    return;
  }

  if (action === 'add-optional-field') {
    await callbacks.onAddOptionalField(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-field-key'),
    );
    return;
  }

  if (action === 'remove-step-field') {
    await callbacks.onRemoveStepField(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-field-key'),
    );
    return;
  }

  if (action === 'add-logic-case') {
    await callbacks.onAddLogicCase(actionEl.getAttribute('data-step-id'));
    return;
  }

  if (action === 'remove-logic-case') {
    await callbacks.onRemoveLogicCase(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
    );
    return;
  }

  if (action === 'save-logic-case-outcome') {
    const row = actionEl.closest('[data-logic-case-row]');
    await callbacks.onSaveLogicCaseOutcome(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
      readInputValue(row, '[data-logic-case-outcome-input="true"]'),
    );
    return;
  }

  if (action === 'save-logic-default') {
    await callbacks.onSaveLogicDefault(
      actionEl.getAttribute('data-step-id'),
      readInputValue(scope, '[data-logic-default-input="true"]'),
    );
    return;
  }

  if (action === 'set-logic-condition-kind') {
    const nodeScope = actionEl.closest('[data-condition-node-path]');
    await callbacks.onSetLogicConditionKind(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
      path,
      readInputValue(nodeScope, '[data-condition-kind-select="true"]'),
    );
    return;
  }

  if (action === 'save-logic-compare-node') {
    const nodeScope = actionEl.closest('[data-condition-node-path]');
    await callbacks.onSaveLogicCompareNode(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
      path,
      readInputValue(nodeScope, '[data-logic-compare-left="true"]'),
      readInputValue(nodeScope, '[data-logic-compare-op="true"]'),
      readInputValue(nodeScope, '[data-logic-compare-right="true"]'),
    );
    return;
  }

  if (action === 'save-logic-exists-node') {
    const nodeScope = actionEl.closest('[data-condition-node-path]');
    await callbacks.onSaveLogicExistsNode(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
      path,
      readInputValue(nodeScope, '[data-logic-exists-value="true"]'),
    );
    return;
  }

  if (action === 'add-logic-condition-child') {
    await callbacks.onAddLogicConditionChild(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
      path,
    );
    return;
  }

  if (action === 'remove-logic-condition-node') {
    await callbacks.onRemoveLogicConditionNode(
      actionEl.getAttribute('data-step-id'),
      Number.parseInt(actionEl.getAttribute('data-case-index') || '-1', 10),
      path,
    );
    return;
  }

  if (action === 'add-webhook-capture-rule') {
    await callbacks.onAddWebhookCaptureRule(actionEl.getAttribute('data-step-id'));
    return;
  }

  if (action === 'save-webhook-capture-rule') {
    const row = actionEl.closest('[data-capture-row]');
    await callbacks.onSaveWebhookCaptureRule(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-capture-target'),
      readInputValue(row, '[data-capture-target-input="true"]'),
      readInputValue(row, '[data-capture-source-input="true"]'),
    );
    return;
  }

  if (action === 'save-all-webhook-capture-rules') {
    const stepId = actionEl.getAttribute('data-step-id');
    const section = actionEl.closest('[data-structured-step-section="webhook-capture"]');
    await callbacks.onSaveAllWebhookCaptureRules(stepId, readWebhookCaptureRows(section));
    return;
  }

  if (action === 'remove-webhook-capture-rule') {
    await callbacks.onRemoveWebhookCaptureRule(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-capture-target'),
    );
    return;
  }

  if (action === 'add-compute-assignment') {
    await callbacks.onAddComputeAssignment(actionEl.getAttribute('data-step-id'));
    return;
  }

  if (action === 'save-compute-assignment') {
    const row = actionEl.closest('[data-compute-row]');
    await callbacks.onSaveComputeAssignment(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-compute-target'),
      readInputValue(row, '[data-compute-target-input="true"]'),
      readInputValue(row, '[data-compute-operator-input="true"]'),
      readInputValue(row, '[data-compute-args-input="true"]'),
    );
    return;
  }

  if (action === 'save-all-compute-assignments') {
    const stepId = actionEl.getAttribute('data-step-id');
    const section = actionEl.closest('[data-structured-step-section="compute-assignments"]');
    await callbacks.onSaveAllComputeAssignments(stepId, readComputeAssignmentRows(section));
    return;
  }

  if (action === 'remove-compute-assignment') {
    await callbacks.onRemoveComputeAssignment(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-compute-target'),
    );
    return;
  }

  if (action === 'add-set-var-entry') {
    await callbacks.onAddSetVarEntry(actionEl.getAttribute('data-step-id'));
    return;
  }

  if (action === 'save-set-var-entry') {
    const row = actionEl.closest('[data-set-var-row]');
    await callbacks.onSaveSetVarEntry(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-set-var-key'),
      readInputValue(row, '[data-set-var-key-input="true"]'),
      readInputValue(row, '[data-set-var-value-input="true"]'),
    );
    return;
  }

  if (action === 'save-all-set-var-entries') {
    const stepId = actionEl.getAttribute('data-step-id');
    const section = actionEl.closest('[data-structured-step-section="set-vars"]');
    await callbacks.onSaveAllSetVarEntries(stepId, readSetVarRows(section));
    return;
  }

  if (action === 'remove-set-var-entry') {
    await callbacks.onRemoveSetVarEntry(
      actionEl.getAttribute('data-step-id'),
      actionEl.getAttribute('data-set-var-key'),
    );
    return;
  }

  if (action === 'set-start') {
    await callbacks.onSetStart(actionEl.getAttribute('data-step-id'));
    return;
  }

  if (action === 'delete-step') {
    const stepId = actionEl.getAttribute('data-step-id');
    const confirmed = window.confirm(
      `Delete step "${stepId}"?\n\nOutgoing edges will be removed. Incoming edges that targeted this step will be removed as well.`,
    );
    if (!confirmed) {
      return;
    }

    await callbacks.onDeleteStep(stepId);
    clearSelection(state);
    clearEditor(state);
    return;
  }

  if (action === 'rename-edge-outcome') {
    const { fromStep, outcome, toStep } = parseEdgeId(actionEl.getAttribute('data-edge-id'));
    await callbacks.onUpdateEdgeOutcome(
      fromStep,
      toStep,
      outcome,
      readInputValue(scope, '[data-edge-outcome-input="true"]'),
    );
    return;
  }

  if (action === 'delete-edge') {
    const { fromStep, outcome, toStep } = parseEdgeId(actionEl.getAttribute('data-edge-id'));
    await callbacks.onDeleteEdge(fromStep, toStep, outcome);
    state.selectedEdgeId = null;
    state.editorEdgeId = null;
    return;
  }

  if (action === 'clear-selection') {
    clearSelection(state);
    clearEditor(state);
    clearCanvasMenu(state);
    render();
  }
}
