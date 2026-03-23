import { $, text } from '../core/dom.js';
import { fetchJson } from '../core/http.js';
import { renderCatalogSummary, renderCurrentContext } from '../context/guide_panel_renderer.js';
import { deriveSemanticContext, parseYamlStatus } from '../context/semantic_context_service.js';
import { createWorkflowEditor } from '../editor/yaml_editor_controller.js';
import { createDraftGraphPreview } from '../graph/draft_graph_preview_controller.js';
import {
  addLinearFlowEdge,
  addOutcomeFlowEdge,
  addStepToWorkflow,
  deleteFlowEdge,
  deleteStepFromWorkflow,
  setStepTitle,
  updateOutcomeFlowEdge,
} from '../features/operations/graph_actions.js';
import {
  addOptionalStepField,
  removeOptionalStepField,
  setStepFieldValue,
} from '../features/operations/step_field_values.js';
import {
  addComputeAssignment,
  addLogicCase,
  addSetVarEntry,
  addWebhookCaptureRule,
  removeComputeAssignment,
  removeLogicCase,
  removeSetVarEntry,
  removeWebhookCaptureRule,
  setLogicCaseOutcome,
  setLogicDefaultOutcome,
  updateComputeAssignment,
  updateSetVarEntry,
  updateWebhookCaptureRule,
} from '../features/operations/step_structured_field_values.js';
import {
  addLogicConditionChild,
  removeLogicConditionNode,
  saveLogicCompareNode,
  saveLogicExistsNode,
  setLogicConditionNodeKind,
} from '../features/operations/logic_condition_tree.js';
import { setWorkflowStart } from '../features/operations/workflow.js';
import { createGuideActionsController } from '../ui/guide_actions_controller.js';
import { createGuideDrawerController } from '../ui/guide_drawer_controller.js';
import { createGraphExpandController } from '../ui/graph_expand_controller.js';
import { createIssuesPanelController } from '../ui/issues_panel_controller.js';

function isTextInputLike(target) {
  if (!target) {
    return false;
  }

  const tag = target.tagName;
  return (
    tag === 'INPUT' ||
    tag === 'TEXTAREA' ||
    tag === 'SELECT' ||
    target.isContentEditable
  );
}

function getPageElements() {
  return {
    root: $('#wf2-editor-root'),
    textarea: $('#id_yaml_text') || $('textarea[name="yaml_text"]'),
    editorMount: $('#wf2-code-editor'),
    form: $('#wf2-form'),
    openGuideBtn: $('#wf2-open-guide'),
    closeGuideBtn: $('#wf2-close-guide'),
    graphCard: $('#wf2-graph-card'),
    graphExpandBtn: $('#wf2-graph-expand'),
    formatBtn: $('#wf2-format-yaml'),

    statusEl: $('#wf2-editor-status'),
    parseStatusEl: $('#wf2-parse-status'),
    cursorInfoEl: $('#wf2-cursor-info'),
    catalogVersionEl: $('#wf2-catalog-version'),
    currentPathEl: $('#wf2-current-path'),
    guideContentEl: $('#wf2-guide-content'),
    graphMount: $('#wf2-graph-editor'),
    graphStatusEl: $('#wf2-graph-status'),
    issuesListEl: $('#wf2-issues-list'),
  };
}

async function init() {
  const els = getPageElements();
  if (!els.root) {
    return;
  }

  if (!els.textarea || !els.editorMount) {
    text(els.statusEl, 'Editor mount or YAML textarea not found.');
    return;
  }

  const state = {
    catalog: null,
    currentContext: null,
  };

  const editor = createWorkflowEditor({
    mount: els.editorMount,
    initialDoc: els.textarea.value || '',
    onDocumentChange(yamlText) {
      els.textarea.value = yamlText;
      updateParseStatus(yamlText);
      updateSemanticContext();
      graphPreview.debouncedRefresh(yamlText);
    },
    onCursorChange(cursor) {
      text(els.cursorInfoEl, `Line ${cursor.line}, column ${cursor.col}`);
      updateSemanticContext();
    },
  });

  const issuesPanel = createIssuesPanelController({
    listEl: els.issuesListEl,
    onSelectIssue(issue) {
      if (typeof issue.offset === 'number') {
        editor.focusOffset(issue.offset);
      }
    },
  });

  const guideDrawer = createGuideDrawerController({
    drawerEl: $('#wf2-guide-drawer'),
    openButton: els.openGuideBtn,
    closeButton: els.closeGuideBtn,
  });

  createGraphExpandController({
    cardEl: els.graphCard,
    toggleButton: els.graphExpandBtn,
  });

  function currentYaml() {
    return editor.getValue();
  }

  function applyYamlMutation(nextYaml, message, replaceOptions = { preserveScroll: true }) {
    editor.replaceValue(nextYaml, replaceOptions);
    text(els.statusEl, message);
  }

  function updateParseStatus(yamlText) {
    const status = parseYamlStatus(yamlText);
    text(els.parseStatusEl, status.message);
    els.parseStatusEl.classList.toggle('text-danger', !status.ok);
    els.parseStatusEl.classList.toggle('text-success', status.ok);
  }

  function updateSemanticContext() {
    const cursor = editor.getCursorInfo();
    state.currentContext = deriveSemanticContext(currentYaml(), cursor.offset);
    renderCurrentContext(state.currentContext, state.catalog, els);
  }

  const graphPreview = createDraftGraphPreview({
    mount: els.graphMount,
    statusEl: els.graphStatusEl,
    catalog: state.catalog,
    callbacks: {
      onIssues(issues) {
        issuesPanel.setGroup('draft-graph', issues || []);
      },

      onIssue({ level, message }) {
        issuesPanel.add(level || 'error', message);
      },

      async onAddStep(stepType) {
        const result = addStepToWorkflow({
          yamlText: currentYaml(),
          catalog: state.catalog,
          stepType,
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

        return result;
      },

      async onSetTitle(stepId, title) {
        const result = setStepTitle({
          yamlText: currentYaml(),
          stepId,
          title,
        });

        applyYamlMutation(result.yamlText, `Updated title for "${stepId}".`);
        return result;
      },

      async onSaveStepField(stepId, fieldKey, rawValue) {
        const result = setStepFieldValue({
          yamlText: currentYaml(),
          catalog: state.catalog,
          stepId,
          fieldKey,
          rawValue,
        });

        applyYamlMutation(result.yamlText, `Saved field "${fieldKey}" for "${stepId}".`);
        return result;
      },

      async onAddOptionalField(stepId, fieldKey) {
        const result = addOptionalStepField({
          yamlText: currentYaml(),
          catalog: state.catalog,
          stepId,
          fieldKey,
        });

        if (!result.changed) {
          text(els.statusEl, `Field "${fieldKey}" already exists on "${stepId}".`);
          return result;
        }

        applyYamlMutation(result.yamlText, `Added optional field "${fieldKey}" to "${stepId}".`);
        return result;
      },

      async onRemoveStepField(stepId, fieldKey) {
        const result = removeOptionalStepField({
          yamlText: currentYaml(),
          catalog: state.catalog,
          stepId,
          fieldKey,
        });

        if (!result.changed) {
          text(els.statusEl, `Field "${fieldKey}" is already absent on "${stepId}".`);
          return result;
        }

        applyYamlMutation(result.yamlText, `Removed optional field "${fieldKey}" from "${stepId}".`);
        return result;
      },

      async onAddLogicCase(stepId) {
        const result = addLogicCase({
          yamlText: currentYaml(),
          stepId,
        });

        applyYamlMutation(result.yamlText, `Added logic case to "${stepId}".`);
        return result;
      },

      async onRemoveLogicCase(stepId, index) {
        const result = removeLogicCase({
          yamlText: currentYaml(),
          stepId,
          index,
        });

        applyYamlMutation(result.yamlText, `Removed logic case ${index + 1} from "${stepId}".`);
        return result;
      },

      async onSaveLogicCaseOutcome(stepId, index, outcome) {
        const result = setLogicCaseOutcome({
          yamlText: currentYaml(),
          stepId,
          index,
          outcome,
        });

        applyYamlMutation(result.yamlText, `Updated outcome for logic case ${index + 1} on "${stepId}".`);
        return result;
      },

      async onSaveLogicDefault(stepId, outcome) {
        const result = setLogicDefaultOutcome({
          yamlText: currentYaml(),
          stepId,
          outcome,
        });

        applyYamlMutation(result.yamlText, `Updated default outcome for "${stepId}".`);
        return result;
      },

      async onSetLogicConditionKind(stepId, caseIndex, path, kind) {
        const result = setLogicConditionNodeKind({
          yamlText: currentYaml(),
          stepId,
          caseIndex,
          path,
          kind,
        });

        applyYamlMutation(result.yamlText, `Updated condition operator for case ${caseIndex + 1} on "${stepId}".`);
        return result;
      },

      async onSaveLogicCompareNode(stepId, caseIndex, path, left, op, right) {
        const result = saveLogicCompareNode({
          yamlText: currentYaml(),
          stepId,
          caseIndex,
          path,
          left,
          op,
          right,
        });

        applyYamlMutation(result.yamlText, `Updated compare condition for case ${caseIndex + 1} on "${stepId}".`);
        return result;
      },

      async onSaveLogicExistsNode(stepId, caseIndex, path, value) {
        const result = saveLogicExistsNode({
          yamlText: currentYaml(),
          stepId,
          caseIndex,
          path,
          value,
        });

        applyYamlMutation(result.yamlText, `Updated exists condition for case ${caseIndex + 1} on "${stepId}".`);
        return result;
      },

      async onAddLogicConditionChild(stepId, caseIndex, path) {
        const result = addLogicConditionChild({
          yamlText: currentYaml(),
          stepId,
          caseIndex,
          path,
        });

        applyYamlMutation(result.yamlText, `Added nested condition to case ${caseIndex + 1} on "${stepId}".`);
        return result;
      },

      async onRemoveLogicConditionNode(stepId, caseIndex, path) {
        const result = removeLogicConditionNode({
          yamlText: currentYaml(),
          stepId,
          caseIndex,
          path,
        });

        applyYamlMutation(result.yamlText, `Removed nested condition from case ${caseIndex + 1} on "${stepId}".`);
        return result;
      },

      async onAddWebhookCaptureRule(stepId) {
        const result = addWebhookCaptureRule({
          yamlText: currentYaml(),
          stepId,
        });
        applyYamlMutation(result.yamlText, `Added capture rule to "${stepId}".`);
        return result;
      },

      async onSaveWebhookCaptureRule(stepId, oldTarget, newTarget, source) {
        const result = updateWebhookCaptureRule({
          yamlText: currentYaml(),
          stepId,
          oldTarget,
          newTarget,
          source,
        });
        applyYamlMutation(result.yamlText, `Updated capture rule on "${stepId}".`);
        return result;
      },

      async onRemoveWebhookCaptureRule(stepId, target) {
        const result = removeWebhookCaptureRule({
          yamlText: currentYaml(),
          stepId,
          target,
        });
        applyYamlMutation(result.yamlText, `Removed capture rule "${target}" from "${stepId}".`);
        return result;
      },

      async onAddComputeAssignment(stepId) {
        const result = addComputeAssignment({
          yamlText: currentYaml(),
          stepId,
        });
        applyYamlMutation(result.yamlText, `Added compute assignment to "${stepId}".`);
        return result;
      },

      async onSaveComputeAssignment(stepId, oldTarget, newTarget, operator, argsText) {
        const result = updateComputeAssignment({
          yamlText: currentYaml(),
          stepId,
          oldTarget,
          newTarget,
          operator,
          argsText,
        });
        applyYamlMutation(result.yamlText, `Updated compute assignment on "${stepId}".`);
        return result;
      },

      async onRemoveComputeAssignment(stepId, target) {
        const result = removeComputeAssignment({
          yamlText: currentYaml(),
          stepId,
          target,
        });
        applyYamlMutation(result.yamlText, `Removed compute assignment "${target}" from "${stepId}".`);
        return result;
      },

      async onAddSetVarEntry(stepId) {
        const result = addSetVarEntry({
          yamlText: currentYaml(),
          stepId,
        });
        applyYamlMutation(result.yamlText, `Added vars entry to "${stepId}".`);
        return result;
      },

      async onSaveSetVarEntry(stepId, oldKey, newKey, value) {
        const result = updateSetVarEntry({
          yamlText: currentYaml(),
          stepId,
          oldKey,
          newKey,
          value,
        });
        applyYamlMutation(result.yamlText, `Updated vars entry "${oldKey}" on "${stepId}".`);
        return result;
      },

      async onRemoveSetVarEntry(stepId, key) {
        const result = removeSetVarEntry({
          yamlText: currentYaml(),
          stepId,
          key,
        });
        applyYamlMutation(result.yamlText, `Removed vars entry "${key}" from "${stepId}".`);
        return result;
      },

      async onSetStart(stepId) {
        const result = setWorkflowStart({
          yamlText: currentYaml(),
          stepId,
        });

        if (!result.changed) {
          text(els.statusEl, `Workflow start is already "${stepId}".`);
          return result;
        }

        applyYamlMutation(result.yamlText, `Set workflow.start to "${stepId}".`);
        return result;
      },

      async onDeleteStep(stepId) {
        const result = deleteStepFromWorkflow({
          yamlText: currentYaml(),
          stepId,
        });

        applyYamlMutation(result.yamlText, `Deleted step "${stepId}".`);
        return result;
      },

      async onAddLinearEdge(fromStep, toStep) {
        const result = addLinearFlowEdge({
          yamlText: currentYaml(),
          fromStep,
          toStep,
        });

        applyYamlMutation(result.yamlText, `Added linear edge from "${fromStep}" to "${toStep}".`);
        return result;
      },

      async onAddOutcomeEdge(fromStep, toStep, outcome) {
        const result = addOutcomeFlowEdge({
          yamlText: currentYaml(),
          fromStep,
          toStep,
          outcome,
        });

        applyYamlMutation(
          result.yamlText,
          `Added outcome edge from "${fromStep}" on "${outcome}" to "${toStep}".`,
        );
        return result;
      },

      async onUpdateEdgeOutcome(fromStep, toStep, oldOutcome, newOutcome) {
        const result = updateOutcomeFlowEdge({
          yamlText: currentYaml(),
          fromStep,
          toStep,
          oldOutcome,
          newOutcome,
        });

        applyYamlMutation(
          result.yamlText,
          `Renamed outcome "${oldOutcome}" to "${newOutcome}" for "${fromStep}".`,
        );
        return result;
      },

      async onDeleteEdge(fromStep, toStep, outcome) {
        const result = deleteFlowEdge({
          yamlText: currentYaml(),
          fromStep,
          toStep,
          outcome,
        });

        applyYamlMutation(
          result.yamlText,
          `Deleted edge from "${fromStep}" to "${toStep}".`,
        );
        return result;
      },
    },
  });

  createGuideActionsController({
    containerEl: els.guideContentEl,
    editor,
    getCatalog: () => state.catalog,
    getContext: () => state.currentContext,
    getYamlText: () => currentYaml(),
    setStatus(message) {
      text(els.statusEl, message);
    },
    addIssue(level, message) {
      issuesPanel.add(level, message);
    },
    applyYamlMutation,
  });

  if (els.graphCard) {
    els.graphCard.addEventListener('mousedown', () => {
      els.graphCard.focus({ preventScroll: true });
    });

    els.graphCard.addEventListener('keydown', async (event) => {
      if (isTextInputLike(event.target)) {
        return;
      }

      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'z') {
        event.preventDefault();

        if (event.shiftKey) {
          editor.redo();
        } else {
          editor.undo();
        }
        return;
      }

      if (event.key === 'Delete' || event.key === 'Backspace') {
        if (!graphPreview.hasSelection()) {
          return;
        }

        event.preventDefault();
        await graphPreview.deleteSelection();
        return;
      }

      if (event.key === 'Escape') {
        event.preventDefault();
        graphPreview.closeEditor();
      }
    });
  }

  if (els.formatBtn) {
    els.formatBtn.addEventListener('click', () => {
      text(
        els.statusEl,
        'Format YAML is intentionally disabled for this step. It will be reconnected after semantic YAML document operations are added.',
      );
    });
  }

  if (els.form) {
    els.form.addEventListener('submit', () => {
      els.textarea.value = currentYaml();
    });
  }

  try {
    state.catalog = await fetchJson(els.root.dataset.contextCatalogUrl);
    renderCatalogSummary(state.catalog, els);
    graphPreview.setCatalog(state.catalog);
    text(
      els.statusEl,
      'CodeMirror loaded. Ctrl+K opens the guide. Right click opens graph settings. Logic steps now support nested condition trees in the graph editor.',
    );
  } catch (err) {
    const msg = `Catalog load failed: ${err instanceof Error ? err.message : String(err)}`;
    text(els.statusEl, msg);
    issuesPanel.add('error', msg);
  }

  const initialCursor = editor.getCursorInfo();
  text(els.cursorInfoEl, `Line ${initialCursor.line}, column ${initialCursor.col}`);
  updateParseStatus(currentYaml());
  updateSemanticContext();
  await graphPreview.refresh(currentYaml());

  guideDrawer.syncAria();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}