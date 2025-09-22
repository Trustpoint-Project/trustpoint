import { register, ui } from './index.js';
import { markTemplatable } from '../template-fields.js';

const METHODS = ['GET','POST','PUT','PATCH','DELETE'];
const RESULT_SOURCES = ['auto','json','text','status','headers'];

register('Webhook', {
  getDefaultParams() {
    return {
      url: '',
      method: 'POST',
      result_to: '',
      result_source: 'auto',
      // (optional future: exports: [{ from_path, to_path }, ...])
    };
  },

  /** Per-type variable hints (relative to ctx.steps.step_X) */
  hints(_step) {
    // Webhook executor writes to outputs.webhook { method, url, status, headers, json, text }
    return [
      'outputs.webhook.method',
      'outputs.webhook.url',
      'outputs.webhook.status',
      'outputs.webhook.headers',
      'outputs.webhook.json',
      'outputs.webhook.text',
    ];
  },

  renderParams(container, step, { updateStepParam, onChange }) {
    container.textContent = '';

    // URL (templatable)
    const urlInput = ui.input({
      type: 'text',
      value: step.params.url || '',
      onInput: (v) => { updateStepParam(step.id, 'url', v); onChange(); },
    });
    markTemplatable(urlInput);

    container.appendChild(ui.labeledNode('Webhook URL', urlInput));

    // Method
    const methodSel = ui.select({
      options: METHODS.map(m => ({ label: m, value: m })),
      value: (step.params.method || 'POST').toUpperCase(),
      onChange: (v) => { updateStepParam(step.id, 'method', v); onChange(); },
    });
    container.appendChild(ui.labeledNode('HTTP Method', methodSel));

    // Result routing
    const rowTop = ui.row();
    rowTop.appendChild(ui.col(ui.labeledNode(
      'Save response to (variable path)',
      ui.input({
        type: 'text',
        value: step.params.result_to || '',
        onInput: (v) => { updateStepParam(step.id, 'result_to', v); onChange(); },
      }),
    )));
    rowTop.appendChild(ui.col(ui.labeledNode(
      'What to save',
      ui.select({
        options: RESULT_SOURCES.map(s => ({ label: s, value: s })),
        value: (step.params.result_source || 'auto'),
        onChange: (v) => { updateStepParam(step.id, 'result_source', v); onChange(); },
      }),
    )));
    container.appendChild(rowTop);

    // (Optional future: exports table)
  },

  validate(params) {
    const errs = [];
    const url = (params.url || '').trim();
    if (!/^https?:\/\//i.test(url)) {
      errs.push('Webhook: url is required and must start with http:// or https://.');
    }
    const method = String(params.method || 'POST').toUpperCase();
    if (!METHODS.includes(method)) {
      errs.push('Webhook: method must be one of GET, POST, PUT, PATCH, DELETE.');
    }
    const resultSource = (params.result_source || 'auto').trim().toLowerCase();
    if (resultSource && !RESULT_SOURCES.includes(resultSource)) {
      errs.push('Webhook: result_source must be one of auto/json/text/status/headers.');
    }
    return errs;
  },
});
