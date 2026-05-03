import {
  addLinearFlowEdge,
  addOutcomeFlowEdge,
  addStepToWorkflow,
  deleteFlowEdge,
  deleteStepFromWorkflow,
  setStepTitle,
  updateOutcomeFlowEdge,
} from '../document/operations/graph.js';
import {
  addLogicConditionChild,
  removeLogicConditionNode,
  saveLogicCompareNode,
  saveLogicExistsNode,
  setLogicConditionNodeKind,
} from '../document/operations/logic_condition_tree.js';
import {
  addComputeAssignment,
  addLogicCase,
  addSetVarEntry,
  addWebhookCaptureRule,
  removeComputeAssignment,
  removeLogicCase,
  removeSetVarEntry,
  removeWebhookCaptureRule,
  replaceComputeAssignments,
  replaceLogicStepContent,
  replaceSetVarEntries,
  replaceWebhookCaptureRules,
  setLogicCaseOutcome,
  setLogicDefaultOutcome,
  updateComputeAssignment,
  updateSetVarEntry,
  updateWebhookCaptureRule,
} from '../document/operations/step_content.js';
import {
  addOptionalStepField,
  removeOptionalStepField,
  setMultipleStepFieldValues,
  setStepFieldValue,
} from '../document/operations/step_fields.js';
import { setWorkflowStart } from '../document/operations/workflow.js';

function applyStepMutation(applyYamlMutation, result, message, options) {
  applyYamlMutation(result.yamlText, message, options);
  return result;
}

export function createGraphCallbacks({
  getYamlText,
  getCatalog,
  applyYamlMutation,
  setStatus,
}) {
  return {
    async onAddStep(stepType) {
      const result = addStepToWorkflow({
        yamlText: getYamlText(),
        catalog: getCatalog(),
        stepType,
      });

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Added new ${stepType} step "${result.stepId}".`,
        {
          preserveScroll: false,
          searchText: `${result.stepId}:`,
          searchOffset: 0,
        },
      );
    },

    async onSetTitle(stepId, title) {
      return applyStepMutation(
        applyYamlMutation,
        setStepTitle({
          yamlText: getYamlText(),
          stepId,
          title,
        }),
        `Updated title for "${stepId}".`,
      );
    },

    async onSaveStepEditor(stepId, stepType, draft) {
      let nextYaml = getYamlText();

      nextYaml = setStepTitle({
        yamlText: nextYaml,
        stepId,
        title: draft?.title,
      }).yamlText;

      if (Array.isArray(draft?.fieldUpdates) && draft.fieldUpdates.length) {
        nextYaml = setMultipleStepFieldValues({
          yamlText: nextYaml,
          catalog: getCatalog(),
          stepId,
          updates: draft.fieldUpdates,
        }).yamlText;
      }

      if (stepType === 'logic') {
        nextYaml = replaceLogicStepContent({
          yamlText: nextYaml,
          stepId,
          cases: draft?.cases,
          defaultOutcome: draft?.defaultOutcome,
        }).yamlText;
      }

      if (stepType === 'webhook' && Array.isArray(draft?.captureRows) && draft.captureRows.length) {
        nextYaml = replaceWebhookCaptureRules({
          yamlText: nextYaml,
          stepId,
          rows: draft.captureRows,
        }).yamlText;
      }

      if (stepType === 'compute' && Array.isArray(draft?.computeRows) && draft.computeRows.length) {
        nextYaml = replaceComputeAssignments({
          yamlText: nextYaml,
          stepId,
          rows: draft.computeRows,
        }).yamlText;
      }

      if (stepType === 'set' && Array.isArray(draft?.setVarRows) && draft.setVarRows.length) {
        nextYaml = replaceSetVarEntries({
          yamlText: nextYaml,
          stepId,
          rows: draft.setVarRows,
        }).yamlText;
      }

      if (nextYaml === getYamlText()) {
        setStatus(`No pending changes for "${stepId}".`);
        return {
          yamlText: nextYaml,
          changed: false,
        };
      }

      applyYamlMutation(nextYaml, `Saved all editor changes for "${stepId}".`);
      return {
        yamlText: nextYaml,
        changed: true,
      };
    },

    async onSaveStepField(stepId, fieldKey, rawValue) {
      return applyStepMutation(
        applyYamlMutation,
        setStepFieldValue({
          yamlText: getYamlText(),
          catalog: getCatalog(),
          stepId,
          fieldKey,
          rawValue,
        }),
        `Saved field "${fieldKey}" for "${stepId}".`,
      );
    },

    async onSaveStepFields(stepId, updates) {
      const result = setMultipleStepFieldValues({
        yamlText: getYamlText(),
        catalog: getCatalog(),
        stepId,
        updates,
      });

      if (!result.changed) {
        setStatus(`No field changes detected for "${stepId}".`);
        return result;
      }

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Saved ${updates.length} field${updates.length === 1 ? '' : 's'} for "${stepId}".`,
      );
    },

    async onAddOptionalField(stepId, fieldKey) {
      const result = addOptionalStepField({
        yamlText: getYamlText(),
        catalog: getCatalog(),
        stepId,
        fieldKey,
      });

      if (!result.changed) {
        setStatus(`Field "${fieldKey}" already exists on "${stepId}".`);
        return result;
      }

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Added optional field "${fieldKey}" to "${stepId}".`,
      );
    },

    async onRemoveStepField(stepId, fieldKey) {
      const result = removeOptionalStepField({
        yamlText: getYamlText(),
        catalog: getCatalog(),
        stepId,
        fieldKey,
      });

      if (!result.changed) {
        setStatus(`Field "${fieldKey}" is already absent on "${stepId}".`);
        return result;
      }

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Removed optional field "${fieldKey}" from "${stepId}".`,
      );
    },

    async onAddLogicCase(stepId) {
      return applyStepMutation(applyYamlMutation, addLogicCase({ yamlText: getYamlText(), stepId }), `Added logic case to "${stepId}".`);
    },

    async onRemoveLogicCase(stepId, index) {
      return applyStepMutation(
        applyYamlMutation,
        removeLogicCase({ yamlText: getYamlText(), stepId, index }),
        `Removed logic case ${index + 1} from "${stepId}".`,
      );
    },

    async onSaveLogicCaseOutcome(stepId, index, outcome) {
      return applyStepMutation(
        applyYamlMutation,
        setLogicCaseOutcome({ yamlText: getYamlText(), stepId, index, outcome }),
        `Updated outcome for logic case ${index + 1} on "${stepId}".`,
      );
    },

    async onSaveLogicDefault(stepId, outcome) {
      return applyStepMutation(
        applyYamlMutation,
        setLogicDefaultOutcome({ yamlText: getYamlText(), stepId, outcome }),
        `Updated default outcome for "${stepId}".`,
      );
    },

    async onSetLogicConditionKind(stepId, caseIndex, path, kind) {
      return applyStepMutation(
        applyYamlMutation,
        setLogicConditionNodeKind({ yamlText: getYamlText(), stepId, caseIndex, path, kind }),
        `Updated condition operator for case ${caseIndex + 1} on "${stepId}".`,
      );
    },

    async onSaveLogicCompareNode(stepId, caseIndex, path, left, op, right) {
      return applyStepMutation(
        applyYamlMutation,
        saveLogicCompareNode({ yamlText: getYamlText(), stepId, caseIndex, path, left, op, right }),
        `Updated compare condition for case ${caseIndex + 1} on "${stepId}".`,
      );
    },

    async onSaveLogicExistsNode(stepId, caseIndex, path, value) {
      return applyStepMutation(
        applyYamlMutation,
        saveLogicExistsNode({ yamlText: getYamlText(), stepId, caseIndex, path, value }),
        `Updated exists condition for case ${caseIndex + 1} on "${stepId}".`,
      );
    },

    async onAddLogicConditionChild(stepId, caseIndex, path) {
      return applyStepMutation(
        applyYamlMutation,
        addLogicConditionChild({ yamlText: getYamlText(), stepId, caseIndex, path }),
        `Added nested condition to case ${caseIndex + 1} on "${stepId}".`,
      );
    },

    async onRemoveLogicConditionNode(stepId, caseIndex, path) {
      return applyStepMutation(
        applyYamlMutation,
        removeLogicConditionNode({ yamlText: getYamlText(), stepId, caseIndex, path }),
        `Removed nested condition from case ${caseIndex + 1} on "${stepId}".`,
      );
    },

    async onAddWebhookCaptureRule(stepId) {
      return applyStepMutation(applyYamlMutation, addWebhookCaptureRule({ yamlText: getYamlText(), stepId }), `Added capture rule to "${stepId}".`);
    },

    async onSaveWebhookCaptureRule(stepId, oldTarget, newTarget, source) {
      return applyStepMutation(
        applyYamlMutation,
        updateWebhookCaptureRule({ yamlText: getYamlText(), stepId, oldTarget, newTarget, source }),
        `Updated capture rule on "${stepId}".`,
      );
    },

    async onSaveAllWebhookCaptureRules(stepId, rows) {
      const result = replaceWebhookCaptureRules({
        yamlText: getYamlText(),
        stepId,
        rows,
      });

      if (!result.changed) {
        setStatus(`No capture rules to save for "${stepId}".`);
        return result;
      }

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Saved ${rows.length} capture rule${rows.length === 1 ? '' : 's'} for "${stepId}".`,
      );
    },

    async onRemoveWebhookCaptureRule(stepId, target) {
      return applyStepMutation(
        applyYamlMutation,
        removeWebhookCaptureRule({ yamlText: getYamlText(), stepId, target }),
        `Removed capture rule "${target}" from "${stepId}".`,
      );
    },

    async onAddComputeAssignment(stepId) {
      return applyStepMutation(applyYamlMutation, addComputeAssignment({ yamlText: getYamlText(), stepId }), `Added compute assignment to "${stepId}".`);
    },

    async onSaveComputeAssignment(stepId, oldTarget, newTarget, operator, argsText) {
      return applyStepMutation(
        applyYamlMutation,
        updateComputeAssignment({ yamlText: getYamlText(), stepId, oldTarget, newTarget, operator, argsText }),
        `Updated compute assignment on "${stepId}".`,
      );
    },

    async onSaveAllComputeAssignments(stepId, rows) {
      const result = replaceComputeAssignments({
        yamlText: getYamlText(),
        stepId,
        rows,
      });

      if (!result.changed) {
        setStatus(`No compute assignments to save for "${stepId}".`);
        return result;
      }

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Saved ${rows.length} compute assignment${rows.length === 1 ? '' : 's'} for "${stepId}".`,
      );
    },

    async onRemoveComputeAssignment(stepId, target) {
      return applyStepMutation(
        applyYamlMutation,
        removeComputeAssignment({ yamlText: getYamlText(), stepId, target }),
        `Removed compute assignment "${target}" from "${stepId}".`,
      );
    },

    async onAddSetVarEntry(stepId) {
      return applyStepMutation(applyYamlMutation, addSetVarEntry({ yamlText: getYamlText(), stepId }), `Added vars entry to "${stepId}".`);
    },

    async onSaveSetVarEntry(stepId, oldKey, newKey, value) {
      return applyStepMutation(
        applyYamlMutation,
        updateSetVarEntry({ yamlText: getYamlText(), stepId, oldKey, newKey, value }),
        `Updated vars entry "${oldKey}" on "${stepId}".`,
      );
    },

    async onSaveAllSetVarEntries(stepId, rows) {
      const result = replaceSetVarEntries({
        yamlText: getYamlText(),
        stepId,
        rows,
      });

      if (!result.changed) {
        setStatus(`No vars to save for "${stepId}".`);
        return result;
      }

      return applyStepMutation(
        applyYamlMutation,
        result,
        `Saved ${rows.length} var entr${rows.length === 1 ? 'y' : 'ies'} for "${stepId}".`,
      );
    },

    async onRemoveSetVarEntry(stepId, key) {
      return applyStepMutation(
        applyYamlMutation,
        removeSetVarEntry({ yamlText: getYamlText(), stepId, key }),
        `Removed vars entry "${key}" from "${stepId}".`,
      );
    },

    async onSetStart(stepId) {
      const result = setWorkflowStart({ yamlText: getYamlText(), stepId });
      if (!result.changed) {
        setStatus(`Workflow start is already "${stepId}".`);
        return result;
      }

      return applyStepMutation(applyYamlMutation, result, `Set workflow.start to "${stepId}".`);
    },

    async onDeleteStep(stepId) {
      return applyStepMutation(
        applyYamlMutation,
        deleteStepFromWorkflow({ yamlText: getYamlText(), stepId }),
        `Deleted step "${stepId}".`,
      );
    },

    async onAddLinearEdge(fromStep, toStep) {
      return applyStepMutation(
        applyYamlMutation,
        addLinearFlowEdge({ yamlText: getYamlText(), fromStep, toStep }),
        `Added linear edge from "${fromStep}" to "${toStep}".`,
      );
    },

    async onAddOutcomeEdge(fromStep, toStep, outcome) {
      return applyStepMutation(
        applyYamlMutation,
        addOutcomeFlowEdge({ yamlText: getYamlText(), fromStep, toStep, outcome }),
        `Added outcome edge from "${fromStep}" on "${outcome}" to "${toStep}".`,
      );
    },

    async onUpdateEdgeOutcome(fromStep, toStep, oldOutcome, newOutcome) {
      return applyStepMutation(
        applyYamlMutation,
        updateOutcomeFlowEdge({ yamlText: getYamlText(), fromStep, toStep, oldOutcome, newOutcome }),
        `Renamed outcome "${oldOutcome}" to "${newOutcome}" for "${fromStep}".`,
      );
    },

    async onDeleteEdge(fromStep, toStep, outcome) {
      return applyStepMutation(
        applyYamlMutation,
        deleteFlowEdge({ yamlText: getYamlText(), fromStep, toStep, outcome }),
        `Deleted edge from "${fromStep}" to "${toStep}".`,
      );
    },
  };
}
