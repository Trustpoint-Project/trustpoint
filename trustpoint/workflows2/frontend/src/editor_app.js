import { $, text } from './core/dom.js';
import { fetchJson } from './core/http.js';
import { renderCatalogSummary, renderCurrentContext } from './features/context/panel.js';
import { createWorkflowEditor } from './features/editor/workflow_editor.js';
import { createInteractiveGraph } from './features/graph/interactive_graph.js';
import {
  addLinearFlowEdge,
  addOutcomeFlowEdge,
  addStepToWorkflow,
  deleteFlowEdge,
  deleteStepFromWorkflow,
  repairWorkflowStart,
  setStepTitle,
} from './features/operations/graph_actions.js';
import {
  buildExpressionFunctionInsertion,
  insertComputeOperator,
  insertConditionOperator,
  setCurrentScalarValue,
} from './features/operations/dsl.js';
import {
  insertComputeAssignment,
  insertLogicCase,
  insertWebhookCaptureRule,
} from './features/operations/nested.js';
import { addMissingRequiredFields, addOptionalField } from './features/operations/step_fields.js';
import { addStepFromType, setCurrentStepType } from './features/operations/steps.js';
import { setWorkflowStart } from './features/operations/workflow.js';
import { deriveSemanticContext, parseYamlStatus } from './features/yaml/semantic_context.js';

async function init() {
  const root = $('#wf2-editor-root');
  if (!root) return;

  const textarea = $('#id_yaml_text') || $('textarea[name="yaml_text"]');
  const editorMount = $('#wf2-code-editor');
  const openGuideBtn = $('#wf2-open-guide');
  const closeGuideBtn = $('#wf2-close-guide');
  const graphCard = $('#wf2-graph-card');
  const graphExpandBtn = $('#wf2-graph-expand');
  const formatBtn = $('#wf2-format-yaml');
  const form = $('#wf2-form');

  const els = {
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

  if (!textarea || !editorMount) {
    text(els.statusEl, 'Editor mount or YAML textarea not found.');
    return;
  }

  let catalog = null;
  let currentContext = null;
  const issues = [];

  function renderIssues() {
    if (!els.issuesListEl) {
      return;
    }

    if (!issues.length) {
      els.issuesListEl.innerHTML = '<div class="text-muted">No current issues.</div>';
      return;
    }

    els.issuesListEl.innerHTML = issues
      .map((item) => {
        const cls =
          item.level === 'error'
            ? 'wf2-issue-error'
            : item.level === 'warning'
              ? 'wf2-issue-warning'
              : 'wf2-issue-info';

        return `
          <div class="wf2-issue-item ${cls}">
            <div class="fw-semibold text-capitalize">${item.level}</div>
            <div>${item.message}</div>
          </div>
        `;
      })
      .join('');
  }

  function addIssue(level, message) {
    const safeMessage = String(message || '').trim();
    if (!safeMessage) {
      return;
    }

    const last = issues[0];
    if (last && last.level === level && last.message === safeMessage) {
      return;
    }

    issues.unshift({
      level,
      message: safeMessage,
    });

    if (issues.length > 8) {
      issues.length = 8;
    }

    renderIssues();
  }

  function openGuide() {
    document.body.classList.add('wf2-guide-open');
    const guideDrawer = $('#wf2-guide-drawer');
    if (guideDrawer) {
      guideDrawer.setAttribute('aria-hidden', 'false');
    }
  }

  function closeGuide() {
    document.body.classList.remove('wf2-guide-open');
    const guideDrawer = $('#wf2-guide-drawer');
    if (guideDrawer) {
      guideDrawer.setAttribute('aria-hidden', 'true');
    }
  }

  function toggleGraphExpand() {
    if (!graphCard || !graphExpandBtn) {
      return;
    }

    const expanded = graphCard.classList.toggle('wf2-graph-expanded');
    document.body.classList.toggle('wf2-graph-expanded', expanded);
    graphExpandBtn.textContent = expanded ? 'Collapse' : 'Expand';
    graphExpandBtn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  }

  const editor = createWorkflowEditor({
    mount: editorMount,
    initialDoc: textarea.value || '',
    onDocumentChange(yamlText) {
      textarea.value = yamlText;
      updateParseStatus(yamlText);
      updateSemanticContext();
      graphUi.debouncedRefresh(yamlText);
    },
    onCursorChange(cursor) {
      text(els.cursorInfoEl, `Line ${cursor.line}, column ${cursor.col}`);
      updateSemanticContext();
    },
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
    currentContext = deriveSemanticContext(currentYaml(), cursor.offset);
    renderCurrentContext(currentContext, catalog, els);
  }

  const graphUi = createInteractiveGraph({
    mount: els.graphMount,
    graphUrl: root.dataset.graphFromYamlUrl,
    statusEl: els.graphStatusEl,
    catalog,
    callbacks: {
      onIssue({ level, message }) {
        addIssue(level || 'error', message);
      },

      async onRepairStart() {
        const result = repairWorkflowStart({
          yamlText: currentYaml(),
        });

        if (!result.changed) {
          text(els.statusEl, `workflow.start already points to "${result.stepId}".`);
          return;
        }

        applyYamlMutation(
          result.yamlText,
          `Repaired workflow.start to "${result.stepId}".`,
        );
      },

      async onAddStep(stepType) {
        const result = addStepToWorkflow({
          yamlText: currentYaml(),
          catalog,
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
      },

      async onSetTitle(stepId, title) {
        const result = setStepTitle({
          yamlText: currentYaml(),
          stepId,
          title,
        });

        applyYamlMutation(result.yamlText, `Updated title for "${stepId}".`);
      },

      async onSetType(stepId, stepType) {
        const result = setCurrentStepType({
          yamlText: currentYaml(),
          catalog,
          stepId,
          stepType,
        });

        if (!result.changed) {
          text(els.statusEl, `Step "${stepId}" already uses type "${stepType}".`);
          return;
        }

        applyYamlMutation(result.yamlText, `Set type of "${stepId}" to "${stepType}".`);
      },

      async onSetStart(stepId) {
        const result = setWorkflowStart({
          yamlText: currentYaml(),
          stepId,
        });

        if (!result.changed) {
          text(els.statusEl, `Workflow start is already "${stepId}".`);
          return;
        }

        applyYamlMutation(result.yamlText, `Set workflow.start to "${stepId}".`);
      },

      async onDeleteStep(stepId) {
        const result = deleteStepFromWorkflow({
          yamlText: currentYaml(),
          stepId,
        });

        applyYamlMutation(result.yamlText, `Deleted step "${stepId}".`);
      },

      async onAddLinearEdge(fromStep, toStep) {
        const result = addLinearFlowEdge({
          yamlText: currentYaml(),
          fromStep,
          toStep,
        });

        applyYamlMutation(result.yamlText, `Added linear edge from "${fromStep}" to "${toStep}".`);
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
          result.mode === 'rerouted_to_end'
            ? `Outcome "${outcome}" from "${fromStep}" now ends at $end.`
            : `Deleted edge from "${fromStep}" to "${toStep}".`,
        );
      },
    },
  });

  if (openGuideBtn) {
    openGuideBtn.addEventListener('click', openGuide);
  }

  if (closeGuideBtn) {
    closeGuideBtn.addEventListener('click', closeGuide);
  }

  if (graphExpandBtn) {
    graphExpandBtn.addEventListener('click', toggleGraphExpand);
  }

  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      openGuide();
      return;
    }

    if (event.key === 'Escape') {
      if (document.body.classList.contains('wf2-guide-open')) {
        closeGuide();
      }
      if (graphCard?.classList.contains('wf2-graph-expanded')) {
        toggleGraphExpand();
      }
    }
  });

  if (formatBtn) {
    formatBtn.addEventListener('click', () => {
      text(
        els.statusEl,
        'Format YAML is intentionally disabled for this step. It will be reconnected after semantic YAML document operations are added.',
      );
    });
  }

  if (form) {
    form.addEventListener('submit', () => {
      textarea.value = currentYaml();
    });
  }

  if (els.guideContentEl) {
    els.guideContentEl.addEventListener('click', (event) => {
      const button = event.target.closest('[data-wf2-action]');
      if (!button) {
        return;
      }

      const action = button.getAttribute('data-wf2-action');

      if (action === 'insert-variable') {
        const insertText = button.getAttribute('data-insert-text');
        if (!insertText) {
          const msg = 'No variable text found.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        editor.insertText(insertText);
        text(els.statusEl, `Inserted ${insertText}`);
        return;
      }

      if (action === 'insert-expression-function') {
        const functionName = button.getAttribute('data-function-name');
        if (!functionName) {
          const msg = 'No function selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        const insertText = buildExpressionFunctionInsertion(functionName);
        editor.insertText(insertText);
        text(els.statusEl, `Inserted ${insertText}`);
        return;
      }

      if (action === 'insert-condition-operator') {
        const conditionKey = button.getAttribute('data-condition-key');
        const mode = button.getAttribute('data-condition-mode') || 'mapping';

        if (!catalog || !conditionKey) {
          const msg = 'No condition operator selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const nextYaml = insertConditionOperator({
            yamlText: currentYaml(),
            cursorOffset: editor.getCursorInfo().offset,
            catalog,
            conditionKey,
            mode,
            context: currentContext,
          });

          applyYamlMutation(nextYaml, `Inserted ${conditionKey} scaffold.`);
        } catch (err) {
          const msg = `Failed to insert condition scaffold: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'insert-compute-operator') {
        const operatorName = button.getAttribute('data-compute-op');
        if (!operatorName) {
          const msg = 'No compute operator selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const nextYaml = insertComputeOperator({
            yamlText: currentYaml(),
            cursorOffset: editor.getCursorInfo().offset,
            operatorName,
            context: currentContext,
          });

          applyYamlMutation(nextYaml, `Inserted compute operator "${operatorName}".`);
        } catch (err) {
          const msg = `Failed to insert compute operator: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'add-logic-case') {
        try {
          const nextYaml = insertLogicCase({
            yamlText: currentYaml(),
            cursorOffset: editor.getCursorInfo().offset,
            context: currentContext,
          });

          applyYamlMutation(nextYaml, 'Inserted logic case.');
        } catch (err) {
          const msg = `Failed to insert logic case: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'add-compute-assignment') {
        try {
          const nextYaml = insertComputeAssignment({
            yamlText: currentYaml(),
            cursorOffset: editor.getCursorInfo().offset,
            context: currentContext,
          });

          applyYamlMutation(nextYaml, 'Inserted compute assignment.');
        } catch (err) {
          const msg = `Failed to insert compute assignment: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'add-webhook-capture-rule') {
        try {
          const nextYaml = insertWebhookCaptureRule({
            yamlText: currentYaml(),
            cursorOffset: editor.getCursorInfo().offset,
            context: currentContext,
          });

          applyYamlMutation(nextYaml, 'Inserted webhook capture rule.');
        } catch (err) {
          const msg = `Failed to insert webhook capture rule: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'set-current-scalar') {
        const rawValue = button.getAttribute('data-scalar-value');
        if (rawValue == null) {
          const msg = 'No scalar value selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const nextYaml = setCurrentScalarValue({
            yamlText: currentYaml(),
            cursorOffset: editor.getCursorInfo().offset,
            rawValue,
          });

          applyYamlMutation(nextYaml, `Set value to ${rawValue}.`);
        } catch (err) {
          const msg = `Failed to set value: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'set-workflow-start') {
        const stepId = button.getAttribute('data-step-id') || currentContext?.stepId;
        if (!stepId) {
          const msg = 'No step selected for workflow.start.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const result = setWorkflowStart({
            yamlText: currentYaml(),
            stepId,
          });

          if (!result.changed) {
            text(els.statusEl, `Workflow start is already "${stepId}".`);
            return;
          }

          applyYamlMutation(result.yamlText, `Set workflow.start to "${stepId}".`);
        } catch (err) {
          const msg = `Failed to set workflow.start: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'add-step-from-type') {
        const stepType = button.getAttribute('data-step-type');
        if (!catalog || !stepType) {
          const msg = 'No step type selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const result = addStepFromType({
            yamlText: currentYaml(),
            catalog,
            stepType,
            cursorOffset: editor.getCursorInfo().offset,
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
          const msg = `Failed to add step: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (action === 'set-step-type') {
        const stepType = button.getAttribute('data-step-type');
        if (!catalog || !currentContext?.stepId || !stepType) {
          const msg = 'No current step or step type selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const result = setCurrentStepType({
            yamlText: currentYaml(),
            catalog,
            stepId: currentContext.stepId,
            stepType,
          });

          if (!result.changed) {
            text(els.statusEl, `Step "${currentContext.stepId}" already uses type "${stepType}".`);
            return;
          }

          applyYamlMutation(result.yamlText, `Set type of "${currentContext.stepId}" to "${stepType}".`);
        } catch (err) {
          const msg = `Failed to set step type: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
        return;
      }

      if (!catalog || !currentContext?.stepId) {
        const msg = 'No current step selected.';
        text(els.statusEl, msg);
        addIssue('warning', msg);
        return;
      }

      if (action === 'add-missing-required-fields') {
        try {
          const result = addMissingRequiredFields({
            yamlText: currentYaml(),
            catalog,
            stepId: currentContext.stepId,
          });

          if (!result.addedKeys.length) {
            text(els.statusEl, 'All required fields are already present.');
            return;
          }

          applyYamlMutation(
            result.yamlText,
            `Added required fields for step "${currentContext.stepId}": ${result.addedKeys.join(', ')}`,
          );
        } catch (err) {
          const msg = `Failed to add required fields: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }

        return;
      }

      if (action === 'add-optional-field') {
        const fieldKey = button.getAttribute('data-field-key');
        if (!fieldKey) {
          const msg = 'No optional field selected.';
          text(els.statusEl, msg);
          addIssue('warning', msg);
          return;
        }

        try {
          const result = addOptionalField({
            yamlText: currentYaml(),
            catalog,
            stepId: currentContext.stepId,
            fieldKey,
          });

          if (!result.addedKey) {
            text(els.statusEl, `Field "${fieldKey}" already exists.`);
            return;
          }

          applyYamlMutation(
            result.yamlText,
            `Added optional field "${result.addedKey}" to step "${currentContext.stepId}".`,
          );
        } catch (err) {
          const msg = `Failed to add optional field: ${err instanceof Error ? err.message : String(err)}`;
          text(els.statusEl, msg);
          addIssue('error', msg);
        }
      }
    });
  }

  try {
    catalog = await fetchJson(root.dataset.contextCatalogUrl);
    renderCatalogSummary(catalog, els);
    graphUi.setCatalog(catalog);
    text(
      els.statusEl,
      'CodeMirror loaded. Ctrl+K opens the guide. Graph keeps the last valid render and reports issues separately.',
    );
  } catch (err) {
    const msg = `Catalog load failed: ${err instanceof Error ? err.message : String(err)}`;
    text(els.statusEl, msg);
    addIssue('error', msg);
  }

  renderIssues();

  const initialCursor = editor.getCursorInfo();
  text(els.cursorInfoEl, `Line ${initialCursor.line}, column ${initialCursor.col}`);
  updateParseStatus(currentYaml());
  updateSemanticContext();
  await graphUi.refresh(currentYaml());
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}