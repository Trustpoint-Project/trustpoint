// static/js/workflow/executors/logic/ui/then.js
import { ui } from '../../index.js';
import { state } from '../../../state.js';

function ensureObj(v) {
  return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {};
}

function stepOptions() {
  const steps = Array.isArray(state.steps) ? state.steps : [];
  return steps.map((s, idx) => ({
    label: `Step ${idx + 1} • ${String(s?.type || 'Step')}`,
    value: `step-${idx + 1}`,
  }));
}

export function renderThen(container, thenObj, onUpdateThen, touch, opts = {}) {
  container.textContent = '';

  const prefix = String(opts.fieldPrefix || '').trim();
  const headline = String(opts.headline || 'If true').trim() || 'If true';

  const t = ensureObj(thenObj);

  const mode =
    t.pass === true ? 'pass'
      : ('goto' in t) ? 'goto'
        : ('stop' in t) ? 'stop'
          : 'pass';

  const body = document.createElement('div');
  body.className = 'mt-2';

  const callUpdate = (val, structural = false) => {
    try { onUpdateThen?.(val, { structural }); } catch { onUpdateThen?.(val); }
  };

  const modeSel = ui.select({
    options: [
      { label: 'Continue to next step', value: 'pass' },
      { label: 'Go to step', value: 'goto' },
      { label: 'Stop workflow', value: 'stop' },
    ],
    value: mode,
    onChange: (v) => {
      if (v === 'pass') callUpdate({ pass: true }, false);
      else if (v === 'goto') {
        const opts2 = stepOptions();
        callUpdate({ goto: String(t.goto || opts2[0]?.value || 'step-1') }, false);
      } else if (v === 'stop') {
        callUpdate({ stop: { reason: String((t.stop && t.stop.reason) || '') } }, false);
      }
      touch?.();
      rebuildBody();
    },
  });
  if (prefix) modeSel.dataset.wwField = `${prefix}-mode`;

  function rebuildBody() {
    body.textContent = '';
    const m = modeSel.value;

    if (m === 'pass') {
      body.appendChild(ui.help('Execution continues with the next step.'));
      return;
    }

    if (m === 'goto') {
      const opts2 = stepOptions();
      const gotoSel = ui.select({
        options: opts2.length ? opts2 : [{ label: 'No steps available', value: '' }],
        value: String(t.goto || opts2[0]?.value || 'step-1'),
        onChange: (v) => {
          callUpdate({ goto: String(v || '').trim() || 'step-1' }, false);
          touch?.();
        },
      });
      if (prefix) gotoSel.dataset.wwField = `${prefix}-goto`;
      body.appendChild(ui.labeledNode('Target step', gotoSel));
      return;
    }

    if (m === 'stop') {
      const reasonInp = ui.input({
        type: 'text',
        value: String((t.stop && t.stop.reason) || ''),
        onInput: (v) => {
          callUpdate({ stop: { reason: String(v || '') } }, false);
          touch?.();
        },
      });
      if (prefix) reasonInp.dataset.wwField = `${prefix}-stop-reason`;
      body.appendChild(ui.labeledNode('Reason (optional)', reasonInp));
    }
  }

  container.appendChild(ui.labeledNode(headline, modeSel));
  container.appendChild(body);
  rebuildBody();
}
