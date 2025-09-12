import { register, ui } from './index.js';
import { markTemplatable } from '../template-fields.js';

register('Condition', {
  getDefaultParams() {
    return { expression: '' };
  },

  renderParams(container, step, { updateStepParam, onChange }) {
    container.textContent = '';

    const exprInput = ui.input({
      type: 'text',
      value: step.params.expression || '',
      onInput: (v) => { updateStepParam(step.id, 'expression', v); onChange(); },
    });
    markTemplatable(exprInput); // allow {{ ctx.* }} in expression

    const expr = ui.labeledNode('Condition (JS expr)', exprInput);
    container.appendChild(expr);
  },

  validate(params) {
    const errs = [];
    if (!params.expression || !String(params.expression).trim()) {
      errs.push('Condition: expression is required.');
    }
    return errs;
  },
});
