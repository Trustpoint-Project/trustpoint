// static/js/steps.js
import {
  state, addStep, removeStep, updateStepType, updateStepParam, moveStep,
} from './state.js';
import { buildDesignTimeCatalog, attachVarPicker } from './ui-context.js';

// Minimal styles for drag affordance (inserted once)
let _stylesInjected = false;
function injectStylesOnce() {
  if (_stylesInjected) return;
  _stylesInjected = true;
  const style = document.createElement('style');
  style.textContent = `
    .ww-step-card { border-radius:.6rem; border:1px solid var(--bs-border-color,#dee2e6); }
    .ww-step-header { background: var(--bs-light,#f8f9fa); border-radius:.5rem; padding:.5rem .75rem; }
    .ww-drag-handle { cursor: grab; user-select:none; font-size:1.1rem; opacity:.7; }
    .ww-dragging { opacity:.6; }
    .ww-drop-indicator-top { box-shadow: 0 -2px 0 0 var(--bs-primary,#0d6efd) inset; }
    .ww-drop-indicator-bottom { box-shadow: 0 2px 0 0 var(--bs-primary,#0d6efd) inset; }
  `;
  document.head.appendChild(style);
}

export function renderStepsUI({containerEl, addBtnEl, onChange}) {
  injectStylesOnce();

  containerEl.textContent = '';
  const frag = document.createDocumentFragment();
  state.steps.forEach((step, idx) => frag.appendChild(stepCard(step, idx, {containerEl, addBtnEl, onChange})));
  containerEl.appendChild(frag);

  // Add new step
  addBtnEl.onclick = () => {
    addStep('Approval', {});
    renderStepsUI({containerEl, addBtnEl, onChange});
    onChange();
  };

  // Enable drag/drop (handle-only drag)
  enableDnD(containerEl, addBtnEl, onChange);
}

function stepCard(step, displayIndex, ctx) {
  const { containerEl, addBtnEl, onChange } = ctx;

  const card = document.createElement('div');
  card.className = 'card ww-step-card mb-2 p-2';
  // NOTE: NO draggable on the card itself.
  card.dataset.stepId = String(step.id);

  // Header with label + controls
  const header = document.createElement('div');
  header.className = 'ww-step-header d-flex justify-content-between align-items-center mb-2';

  // Left: drag handle + title (Step N • Type)
  const left = document.createElement('div');
  left.className = 'd-flex align-items-center gap-2';
  const grip = document.createElement('span');
  grip.className = 'ww-drag-handle';
  grip.title = 'Drag to reorder';
  grip.textContent = '⋮⋮';
  // Only the handle is draggable:
  grip.setAttribute('draggable', 'true');

  const title = document.createElement('strong');
  title.textContent = `Step ${displayIndex + 1} • ${step.type}`;
  left.appendChild(grip);
  left.appendChild(title);

  // Right: remove button
  const rm = document.createElement('button');
  rm.type = 'button';
  rm.className = 'btn-close';
  rm.onclick = () => {
    removeStep(step.id);
    renderStepsUI({containerEl, addBtnEl, onChange});
    onChange();
  };

  header.appendChild(left);
  header.appendChild(rm);
  card.appendChild(header);

  // Type selector
  const sel = document.createElement('select');
  sel.className = 'form-select form-select-sm mb-2';
  ['Approval','Email','Webhook','Timer','Condition'].forEach(t => sel.add(new Option(t, t)));
  sel.value = step.type;
  sel.onchange = () => {
    updateStepType(step.id, sel.value);
    renderStepsUI({containerEl, addBtnEl, onChange});
    onChange();
  };
  card.appendChild(sel);

  // Params area
  const paramsDiv = document.createElement('div');
  card.appendChild(paramsDiv);
  renderParams(step, paramsDiv, {containerEl, addBtnEl, onChange});

  return card;
}

function enableDnD(containerEl, addBtnEl, onChange) {
  let dragId = null;
  let dragCard = null;

  // Delegate dragstart/dragend to handles only
  containerEl.querySelectorAll('.ww-drag-handle[draggable="true"]').forEach(handle => {
    handle.ondragstart = (e) => {
      const card = handle.closest('.ww-step-card');
      if (!card) return;
      dragId = Number(card.dataset.stepId);
      dragCard = card;
      card.classList.add('ww-dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', String(dragId)); } catch {}
      // Optional nicer drag image (use the card)
      try { e.dataTransfer.setDragImage(card, 10, 10); } catch {}
    };
    handle.ondragend = () => {
      if (dragCard) dragCard.classList.remove('ww-dragging');
      dragId = null;
      dragCard = null;
      // Clear any stray indicators
      containerEl.querySelectorAll('.ww-step-card').forEach(c => {
        c.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
      });
    };
  });

  // Cards act as drop targets
  containerEl.querySelectorAll('.ww-step-card').forEach(card => {
    card.ondragover = (e) => {
      if (!dragId) return;
      e.preventDefault(); // allow drop
      const rect = card.getBoundingClientRect();
      const before = (e.clientY - rect.top) < rect.height / 2;
      card.classList.toggle('ww-drop-indicator-top', before);
      card.classList.toggle('ww-drop-indicator-bottom', !before);
    };
    card.ondragleave = () => {
      card.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
    };
    card.ondrop = (e) => {
      e.preventDefault();
      card.classList.remove('ww-drop-indicator-top', 'ww-drop-indicator-bottom');
      if (!dragId) return;

      const targetId = Number(card.dataset.stepId);
      if (dragId === targetId) return;

      const steps = state.steps;
      const fromIndex = steps.findIndex(s => s.id === dragId);
      const toIndexBase = steps.findIndex(s => s.id === targetId);

      const rect = card.getBoundingClientRect();
      const before = (e.clientY - rect.top) < rect.height / 2;
      let toIndex = toIndexBase + (before ? 0 : 1);

      moveStep(dragId, toIndex > fromIndex ? toIndex - 1 : toIndex);

      // Re-render and notify
      renderStepsUI({containerEl, addBtnEl, onChange});
      onChange();
    };
  });
}

function renderParams(step, container, ctx) {
  const { onChange } = ctx;
  container.textContent = '';

  if (step.type === 'Email') {
    renderEmailParams(step, container, ctx);
    return;
  }

  const defs = {
    Approval: [
      { name:'approverRole', label:'Approver Role', type:'text' },
      { name:'timeoutSecs',  label:'Timeout (sec)',  type:'number' },
    ],
    Webhook: [
      { name:'url',            label:'Webhook URL',                       type:'text' },
      { name:'method',         label:'HTTP Method',                       type:'select', options:['GET','POST','PUT','PATCH','DELETE'] },
      { name:'result_to',      label:'Save response to (variable path)',  type:'text' },
      { name:'result_source',  label:'What to save',                      type:'select', options:['auto','json','text','status','headers'] },
    ],
    Timer: [{ name:'delaySecs', label:'Delay (sec)', type:'number' }],
    Condition: [{ name:'expression', label:'Condition (JS expr)', type:'text' }],
  }[step.type] || [];

  defs.forEach(def => {
    const lbl = document.createElement('label');
    lbl.className = 'form-label small d-block';
    lbl.textContent = def.label + ': ';

    let inp;
    if (def.type === 'select') {
      inp = document.createElement('select');
      inp.className = 'form-select form-select-sm';
      def.options.forEach(o => inp.add(new Option(o,o)));
    } else {
      inp = document.createElement('input');
      inp.type = def.type;
      inp.className = 'form-control form-control-sm';
    }
    inp.value = step.params[def.name] ?? '';
    inp.oninput = () => {
      const v = def.type === 'number' ? Number(inp.value || 0) : inp.value;
      updateStepParam(step.id, def.name, v);
      onChange();
    };

    lbl.appendChild(inp);
    container.appendChild(lbl);
  });
}

// -------- Email step --------
function renderEmailParams(step, container, ctx) {
  const { onChange } = ctx;

  // Clear container (important to avoid duplicates on mode toggle)
  container.textContent = '';

  // Recipients (csv)
  const recips = labeledTextArea('Recipients (comma-separated)', step.params.recipients || '', v => {
    updateStepParam(step.id, 'recipients', v); onChange();
  });
  container.appendChild(recips);

  // From / CC / BCC
  const row = document.createElement('div'); row.className = 'row g-2';
  row.appendChild(colNode(labeledInput('From (optional)', step.params.from_email || '', v => {
    updateStepParam(step.id, 'from_email', v); onChange();
  }, 'email')));
  row.appendChild(colNode(labeledInput('CC (optional, comma-separated)', step.params.cc || '', v => {
    updateStepParam(step.id, 'cc', v); onChange();
  })));
  row.appendChild(colNode(labeledInput('BCC (optional, comma-separated)', step.params.bcc || '', v => {
    updateStepParam(step.id, 'bcc', v); onChange();
  })));
  container.appendChild(row);

  // Mode: template vs custom
  const useTpl = !!(step.params.template && String(step.params.template).trim());
  const modeWrap = document.createElement('div'); modeWrap.className = 'my-2';
  const tpl = radio('email-mode-'+step.id, 'Use template', useTpl, () => {
    updateStepParam(step.id, 'subject', '');
    updateStepParam(step.id, 'body', '');
    if (!step.params.template) {
      const first = firstTemplateKey();
      if (first) updateStepParam(step.id, 'template', first);
    }
    renderEmailParams(step, container, ctx);
    onChange();
  });
  const custom = radio('email-mode-'+step.id, 'Write custom', !useTpl, () => {
    updateStepParam(step.id, 'template', '');
    renderEmailParams(step, container, ctx);
    onChange();
  });
  modeWrap.appendChild(tpl.wrap); modeWrap.appendChild(custom.wrap);
  container.appendChild(modeWrap);

  // Template selects
  const tplBlock = document.createElement('div'); tplBlock.className = useTpl ? '' : 'd-none';
  const groups = (state.mailTemplates && Array.isArray(state.mailTemplates.groups)) ? state.mailTemplates.groups : [];

  const groupSel = document.createElement('select'); groupSel.className = 'form-select form-select-sm';
  groups.forEach(g => groupSel.add(new Option(g.label || g.key, g.key)));

  const tplSel = document.createElement('select'); tplSel.className = 'form-select form-select-sm';

  const currentTpl = step.params.template || '';
  const currentGroup = groupForTemplate(currentTpl) || (groups[0]?.key || '');
  groupSel.value = currentGroup;
  fillTemplatesForGroup(currentGroup, tplSel);
  if (currentTpl && [...tplSel.options].some(o => o.value === currentTpl)) tplSel.value = currentTpl;

  groupSel.onchange = () => {
    fillTemplatesForGroup(groupSel.value, tplSel);
    updateStepParam(step.id, 'template', tplSel.value || '');
    onChange();
  };
  tplSel.onchange = () => { updateStepParam(step.id, 'template', tplSel.value || ''); onChange(); };

  const tplRow = document.createElement('div'); tplRow.className = 'row g-2 mt-1';
  tplRow.appendChild(colNode(labeledNode('Template group', groupSel)));
  tplRow.appendChild(colNode(labeledNode('Template', tplSel)));
  tplBlock.appendChild(tplRow);
  container.appendChild(tplBlock);

  // Custom subject/body + variable pickers
  const customBlock = document.createElement('div'); customBlock.className = useTpl ? 'd-none mt-2' : 'mt-2';
  const subjLbl = labeledInput('Subject', step.params.subject || '', v => { updateStepParam(step.id, 'subject', v); onChange(); });
  const bodyLbl = labeledTextArea('Body (plain text)', step.params.body || '', v => { updateStepParam(step.id, 'body', v); onChange(); });
  customBlock.appendChild(subjLbl);
  customBlock.appendChild(bodyLbl);
  container.appendChild(customBlock);

  // >>> THIS is where you hook in the dynamic catalog <<<
  if (!useTpl) {
    try {
      const catalog = buildDesignTimeCatalog({ state });
      attachVarPicker({ container: subjLbl, targetInput: subjLbl.querySelector('input'),   catalog });
      attachVarPicker({ container: bodyLbl, targetInput:  bodyLbl.querySelector('textarea'), catalog });
    } catch {
      // ignore picker failures (non-blocking)
    }
  }

  // helpers
  function firstTemplateKey() {
    for (const g of (state.mailTemplates?.groups || [])) {
      if ((g.templates || []).length) return g.templates[0].key;
    }
    return '';
  }
  function groupForTemplate(tplKey) {
    const gg = state.mailTemplates?.groups || [];
    for (const g of gg) if ((g.templates||[]).some(t => t.key === tplKey)) return g.key;
    return '';
  }
  function fillTemplatesForGroup(groupKey, sel) {
    sel.innerHTML = '';
    const g = (state.mailTemplates?.groups || []).find(x => x.key === groupKey);
    (g?.templates || []).forEach(t => sel.add(new Option(t.label || t.key, t.key)));
    if (!sel.value && sel.options.length) sel.selectedIndex = 0;
  }
}

function labeledInput(label, val, onInput, type='text') {
  const lbl = document.createElement('label');
  lbl.className = 'form-label small d-block';
  lbl.textContent = label + ': ';
  const inp = document.createElement('input');
  inp.className = 'form-control form-control-sm';
  inp.type = type;
  inp.value = val || '';
  inp.oninput = () => onInput(inp.value);
  lbl.appendChild(inp);
  return lbl;
}
function labeledTextArea(label, val, onInput) {
  const lbl = document.createElement('label');
  lbl.className = 'form-label small d-block';
  lbl.textContent = label + ': ';
  const ta = document.createElement('textarea');
  ta.className = 'form-control form-control-sm';
  ta.rows = 4;
  ta.value = val || '';
  ta.oninput = () => onInput(ta.value);
  lbl.appendChild(ta);
  return lbl;
}
function labeledNode(label, node) {
  const lbl = document.createElement('label');
  lbl.className = 'form-label small d-block';
  lbl.textContent = label + ': ';
  lbl.appendChild(node);
  return lbl;
}
function colNode(node) { const col = document.createElement('div'); col.className = 'col-md-6'; col.appendChild(node); return col; }
function radio(name, text, checked, onChange) {
  const id = `${name}-${Math.random().toString(36).slice(2,8)}`;
  const wrap = document.createElement('div'); wrap.className = 'form-check form-check-inline';
  const input = document.createElement('input'); input.className = 'form-check-input'; input.type = 'radio'; input.name = name; input.id = id; input.checked = !!checked; input.onchange = onChange;
  const label = document.createElement('label'); label.className = 'form-check-label'; label.htmlFor = id; label.textContent = text;
  wrap.appendChild(input); wrap.appendChild(label);
  return { wrap, input };
}
