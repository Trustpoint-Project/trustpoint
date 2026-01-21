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

export function renderThen(container, thenObj, onUpdateThen, touch) {
  container.textContent = '';
  const t = ensureObj(thenObj);

  const mode =
    t.pass === true ? 'pass'
      : ('goto' in t) ? 'goto'
        : ('stop' in t) ? 'stop'
          : 'pass';

  const modeSel = ui.select({
    options: [
      { label: 'Continue to next step', value: 'pass' },
      { label: 'Go to step', value: 'goto' },
      { label: 'Stop workflow', value: 'stop' },
    ],
    value: mode,
    onChange: (v) => {
      if (v === 'pass') onUpdateThen({ pass: true });
      else if (v === 'goto') {
        const opts = stepOptions();
        onUpdateThen({ goto: String(t.goto || opts[0]?.value || 'step-1') });
      } else if (v === 'stop') {
        onUpdateThen({ stop: { reason: String((t.stop && t.stop.reason) || '') } });
      }
      touch?.();
      rebuildBody();
    },
  });

  const body = document.createElement('div');
  body.className = 'mt-2';

  function rebuildBody() {
    body.textContent = '';
    const m = modeSel.value;

    if (m === 'pass') {
      body.appendChild(ui.help('Execution continues with the next step.'));
      return;
    }

    if (m === 'goto') {
      const opts = stepOptions();
      const gotoSel = ui.select({
        options: opts.length ? opts : [{ label: 'No steps available', value: '' }],
        value: String(t.goto || opts[0]?.value || 'step-1'),
        onChange: (v) => {
          onUpdateThen({ goto: String(v || '').trim() || 'step-1' });
          touch?.();
        },
      });
      body.appendChild(ui.labeledNode('Target step', gotoSel));
      return;
    }

    if (m === 'stop') {
      const reasonInp = ui.input({
        type: 'text',
        value: String((t.stop && t.stop.reason) || ''),
        onInput: (v) => {
          onUpdateThen({ stop: { reason: String(v || '') } });
          touch?.();
        },
      });
      body.appendChild(ui.labeledNode('Reason (optional)', reasonInp));
    }
  }

  container.appendChild(ui.labeledNode('If matched', modeSel));
  container.appendChild(body);
  rebuildBody();
}
