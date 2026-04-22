import {
  readComputeAssignmentRows,
  readSetVarRows,
  readWebhookCaptureRows,
} from '../steps/structured_step_editor_state.js';
import { readLogicStepDraft } from '../logic/logic_step_editor_state.js';

function readValue(scope, selector) {
  return scope?.querySelector(selector)?.value ?? '';
}

function readFieldUpdates(scope) {
  return [...(scope?.querySelectorAll('[data-step-field-row]') || [])].map((row) => ({
    fieldKey: row.getAttribute('data-step-field-row'),
    rawValue: readValue(row, '[data-step-field-input="true"]'),
  }));
}

export function readGraphStepEditorDraft(scope, stepType) {
  const draft = {
    title: readValue(scope, '[data-node-title-input="true"]'),
    fieldUpdates: readFieldUpdates(scope),
  };

  if (stepType === 'logic') {
    return {
      ...draft,
      ...readLogicStepDraft(scope),
    };
  }

  if (stepType === 'webhook') {
    return {
      ...draft,
      captureRows: readWebhookCaptureRows(scope),
    };
  }

  if (stepType === 'compute') {
    return {
      ...draft,
      computeRows: readComputeAssignmentRows(scope),
    };
  }

  if (stepType === 'set') {
    return {
      ...draft,
      setVarRows: readSetVarRows(scope),
    };
  }

  return draft;
}
