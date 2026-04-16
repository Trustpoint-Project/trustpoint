import { $, text } from '../shared/dom.js';

export function isTextInputLike(target) {
  if (!target) {
    return false;
  }

  const tag = target.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
}

export function getWorkflowEditorPageElements() {
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

export function reportMissingEditorMount(statusEl) {
  text(statusEl, 'Editor mount or YAML textarea not found.');
}
