// static/js/workflow/ui-context.js
import { api } from './api.js';

export async function fetchContextCatalog({ handler, protocol, operation }) {
  if (!handler) return { groups: [] };
  const data = await api.wizardContextCatalog({ handler, protocol, operation }).catch(() => null);
  if (!data || !Array.isArray(data.groups)) return { groups: [] };
  return { groups: data.groups };
}

/**
 * Build a single, non-crowded Steps group.
 * Adds step-type-specific convenience vars (e.g. webhook.* only for Webhook steps).
 */
export function buildStepsGroup({ stepCount, selectedStepNo, selectedStepType }) {
  const stepNo = Number(selectedStepNo || 1) || 1;
  const safeNo = stepCount > 0 ? Math.min(Math.max(stepNo, 1), stepCount) : 1;
  const stepKey = `step_${safeNo}`;

  const vars = [
    { key: 'steps.<step>.status',  label: 'status',  ctxPath: `ctx.steps.${stepKey}.status`,  _tpl: 'ctx.steps.<step>.status' },
    { key: 'steps.<step>.error',   label: 'error',   ctxPath: `ctx.steps.${stepKey}.error`,   _tpl: 'ctx.steps.<step>.error' },
    { key: 'steps.<step>.ok',      label: 'ok',      ctxPath: `ctx.steps.${stepKey}.ok`,      _tpl: 'ctx.steps.<step>.ok' },
    { key: 'steps.<step>.outputs', label: 'outputs', ctxPath: `ctx.steps.${stepKey}.outputs`, _tpl: 'ctx.steps.<step>.outputs' },
  ];

  // Only show webhook convenience keys if the selected step is a Webhook step
  if (String(selectedStepType || '') === 'Webhook') {
    vars.push(
      { key: 'steps.<step>.outputs.webhook.status', label: 'webhook.status', ctxPath: `ctx.steps.${stepKey}.outputs.webhook.status`, _tpl: 'ctx.steps.<step>.outputs.webhook.status' },
      { key: 'steps.<step>.outputs.webhook.text',   label: 'webhook.text',   ctxPath: `ctx.steps.${stepKey}.outputs.webhook.text`,   _tpl: 'ctx.steps.<step>.outputs.webhook.text' },
    );
  }
  if (String(selectedStepType || '') === 'Email') {
    vars.push(
      { key: 'steps.<step>.outputs.email.recipients', label: 'email.recipients', ctxPath: `ctx.steps.${stepKey}.outputs.email.recipients`, _tpl: 'ctx.steps.<step>.outputs.email.recipients' },
      { key: 'steps.<step>.outputs.email.from',   label: 'email.from',   ctxPath: `ctx.steps.${stepKey}.outputs.email.from`,   _tpl: 'ctx.steps.<step>.outputs.email.from' },
      { key: 'steps.<step>.outputs.email.cc',   label: 'email.cc',   ctxPath: `ctx.steps.${stepKey}.outputs.email.cc`,   _tpl: 'ctx.steps.<step>.outputs.email.cc' },
      { key: 'steps.<step>.outputs.email.bcc',   label: 'email.bcc',   ctxPath: `ctx.steps.${stepKey}.outputs.email.bcc`,   _tpl: 'ctx.steps.<step>.outputs.email.bcc' },
    );
  }

  return {
    key: 'steps',
    label: 'Steps',
    vars,
  };
}
