import { register, ui } from './index.js';

register('Approval', {
  getDefaultParams() {
    return { approverRole: '', timeoutSecs: 0 };
  },

  /** Per-type variable hints (relative to ctx.steps.step_X) */
  hints(_step) {
    // If/when the Approval executor writes outputs, surface them here.
    // Keep it minimal for now.
    return [
      // 'outputs.decision', // uncomment if you later add it to context
    ];
  },

  renderParams(container, step, { updateStepParam, onChange }) {
    container.textContent = '';

    const approver = ui.labeledNode(
      'Approver Role',
      ui.input({
        type: 'text',
        value: step.params.approverRole || '',
        onInput: (v) => { updateStepParam(step.id, 'approverRole', v); onChange(); },
      }),
    );

    const to = ui.labeledNode(
      'Timeout (sec)',
      ui.input({
        type: 'number',
        value: step.params.timeoutSecs ?? 0,
        onInput: (v) => { updateStepParam(step.id, 'timeoutSecs', Number(v || 0)); onChange(); },
      }),
    );

    container.appendChild(approver);
    container.appendChild(to);
  },

  validate(params) {
    const errs = [];
    if (params.timeoutSecs != null && Number(params.timeoutSecs) < 0) {
      errs.push('Approval: timeoutSecs must be >= 0.');
    }
    return errs;
  },
});
