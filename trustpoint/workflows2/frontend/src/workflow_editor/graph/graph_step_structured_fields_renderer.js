import { renderStructuredStepEditor } from '../steps/structured_step_editor_renderer.js';

export function renderStructuredStepFields({
  availableVarNames = [],
  triggerKey = null,
  stepId,
  stepType,
  stepData,
  catalog,
}) {
  return renderStructuredStepEditor({
    actionAttribute: 'data-graph-overlay-action',
    availableVarNames,
    catalog,
    saveMode: 'footer',
    stepData,
    stepId,
    stepType,
    triggerKey,
  });
}
