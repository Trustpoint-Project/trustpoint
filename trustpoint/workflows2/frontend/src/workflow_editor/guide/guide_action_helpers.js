export function readValue(scope, selector) {
  return scope?.querySelector(selector)?.value ?? '';
}

export function createGuideActionContext({
  button,
  containerEl,
  editor,
  getCatalog,
  getContext,
  getYamlText,
  setStatus,
  addIssue,
  applyYamlMutation,
}) {
  const catalog = getCatalog();
  const context = getContext();
  const yamlText = getYamlText();
  const scope =
    button.closest('[data-logic-node-scope="true"]') ||
    button.closest('[data-logic-case-row]') ||
    button.closest('[data-wf2-scope="true"]') ||
    button.closest('[data-apply-scope="true"]') ||
    button.closest('.wf2-cond-node') ||
    containerEl;

  function fail(message, level = 'error') {
    setStatus(message);
    addIssue(level, message);
  }

  return {
    button,
    scope,
    catalog,
    context,
    yamlText,
    editor,
    setStatus,
    applyYamlMutation,
    fail,
    cursorOffset() {
      return editor.getCursorInfo().offset;
    },
  };
}
