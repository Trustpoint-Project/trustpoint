import { text } from '../shared/dom.js';
import { fetchJson } from '../shared/http.js';
import { renderCatalogSummary, renderCurrentContext } from '../guide/guide_panel_renderer.js';
import {
  deriveSemanticContext,
  parseYamlStatus,
} from '../guide/semantic_context_service.js';
import { createWorkflowEditor } from '../editor/yaml_editor_controller.js';
import { createDraftGraphPreview } from '../graph/draft_graph_preview_controller.js';
import { createGuideActionsController } from '../guide/guide_actions_controller.js';
import { createGraphCallbacks } from './graph_callbacks.js';
import {
  getWorkflowEditorPageElements,
  isTextInputLike,
  reportMissingEditorMount,
} from './workspace_dom.js';
import { createGraphExpandController } from '../ui/graph_expand_controller.js';
import { createGuideDrawerController } from '../ui/guide_drawer_controller.js';
import { createIssuesPanelController } from '../ui/issues_panel_controller.js';

function updateParseStatus(parseStatusEl, yamlText) {
  const status = parseYamlStatus(yamlText);
  text(parseStatusEl, status.message);
  parseStatusEl.classList.toggle('text-danger', !status.ok);
  parseStatusEl.classList.toggle('text-success', status.ok);
}

function bindGraphKeyboardShortcuts({ graphCard, editor, graphPreview }) {
  if (!graphCard) {
    return;
  }

  graphCard.addEventListener('mousedown', () => {
    graphCard.focus({ preventScroll: true });
  });

  graphCard.addEventListener('keydown', async (event) => {
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

export async function initWorkflowEditorWorkspace() {
  const els = getWorkflowEditorPageElements();
  if (!els.root) {
    return;
  }

  if (!els.textarea || !els.editorMount) {
    reportMissingEditorMount(els.statusEl);
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
      updateParseStatus(els.parseStatusEl, yamlText);
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
    drawerEl: document.querySelector('#wf2-guide-drawer'),
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

  function setStatus(message) {
    text(els.statusEl, message);
  }

  function applyYamlMutation(nextYaml, message, replaceOptions = { preserveScroll: true }) {
    editor.replaceValue(nextYaml, replaceOptions);
    setStatus(message);
  }

  function updateSemanticContext() {
    const cursor = editor.getCursorInfo();
    state.currentContext = deriveSemanticContext(currentYaml(), cursor.offset);
    renderCurrentContext(state.currentContext, state.catalog, els, currentYaml());
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

      ...createGraphCallbacks({
        getYamlText: currentYaml,
        getCatalog: () => state.catalog,
        applyYamlMutation,
        setStatus,
      }),
    },
  });

  createGuideActionsController({
    containerEl: els.guideContentEl,
    editor,
    getCatalog: () => state.catalog,
    getContext: () => state.currentContext,
    getYamlText: currentYaml,
    setStatus,
    addIssue(level, message) {
      issuesPanel.add(level, message);
    },
    applyYamlMutation,
  });

  bindGraphKeyboardShortcuts({
    graphCard: els.graphCard,
    editor,
    graphPreview,
  });

  if (els.formatBtn) {
    els.formatBtn.addEventListener('click', () => {
      setStatus(
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
    setStatus(
      'CodeMirror loaded. Ctrl+K opens the guide. Right click opens graph settings. Logic steps now support nested condition trees in the graph editor.',
    );
  } catch (err) {
    const message = `Catalog load failed: ${err instanceof Error ? err.message : String(err)}`;
    setStatus(message);
    issuesPanel.add('error', message);
  }

  const initialCursor = editor.getCursorInfo();
  text(els.cursorInfoEl, `Line ${initialCursor.line}, column ${initialCursor.col}`);
  updateParseStatus(els.parseStatusEl, currentYaml());
  updateSemanticContext();
  await graphPreview.refresh(currentYaml());

  guideDrawer.syncAria();
}
