import { initWorkflowEditorWorkspace } from './page/workflow_editor_workspace.js';

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initWorkflowEditorWorkspace);
} else {
  initWorkflowEditorWorkspace();
}
