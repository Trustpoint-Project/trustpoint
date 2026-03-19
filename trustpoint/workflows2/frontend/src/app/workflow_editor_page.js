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
} from '../features/operations/graph_actions.js';
import { setCurrentStepType } from '../features/operations/steps.js';
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
          catalog: state.catalog,
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
          `Deleted edge from "${fromStep}" to "${toStep}".`,
        );
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

    els.graphCard.addEventListener('keydown', (event) => {
      if (isTextInputLike(event.target)) {
        return;
      }

      if (!(event.ctrlKey || event.metaKey) || event.key.toLowerCase() !== 'z') {
        return;
      }

      event.preventDefault();

      if (event.shiftKey) {
        editor.redo();
      } else {
        editor.undo();
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
      'CodeMirror loaded. Ctrl+K opens the guide. The graph renders draft YAML and issues are shown separately.',
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