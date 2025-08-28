import {
  state, addStep, removeStep, updateStepType, updateStepParam,
} from './state.js';

// minimal styles for chips (one-time)
let stylesInjected = false;
function injectStyles() {
  if (stylesInjected) return;
  stylesInjected = true;
  const style = document.createElement('style');
  style.textContent = `
    .chip-input { min-height: 2.375rem; display:flex; align-items:center; gap:.35rem; flex-wrap:wrap; padding:.375rem .5rem; border:1px solid var(--bs-border-color, #ced4da); border-radius:.375rem; background:#fff; }
    .chip-input:focus-within { outline: 2px solid rgba(13,110,253,.2); }
    .chip-input input { border:none; outline:none; min-width:12ch; flex:1 0 120px; padding:.25rem; }
    .chip { display:inline-flex; align-items:center; gap:.35rem; border-radius:999px; padding:.15rem .5rem; background:#e9ecef; }
    .chip .remove { border:none; background:transparent; cursor:pointer; font-size:1rem; line-height:1; padding:0 .1rem; opacity:.6; }
    .chip .remove:hover { opacity:1; }
  `;
  document.head.appendChild(style);
}

export function renderStepsUI({containerEl, addBtnEl, onChange}) {
  injectStyles();

  containerEl.textContent = '';
  const frag = document.createDocumentFragment();
  state.steps.forEach(step => frag.appendChild(stepCard(step, {containerEl, addBtnEl, onChange})));
  containerEl.appendChild(frag);

  addBtnEl.onclick = () => {
    addStep('Approval', {});
    renderStepsUI({containerEl, addBtnEl, onChange});
    onChange();
  };
}

function stepCard(step, ctx) {
  const { containerEl, addBtnEl, onChange } = ctx;

  const card = document.createElement('div');
  card.className = 'card mb-2 p-2';

  const header = document.createElement('div');
  header.className = 'd-flex justify-content-between align-items-center mb-2';
  header.innerHTML = '<strong>Step</strong>';
  const rm = document.createElement('button');
  rm.type = 'button'; rm.className = 'btn-close';
  rm.onclick = () => {
    removeStep(step.id);
    renderStepsUI({containerEl, addBtnEl, onChange});
    onChange();
  };
  header.appendChild(rm);
  card.appendChild(header);

  const sel = document.createElement('select');
  sel.className = 'form-select form-select-sm mb-2';
  ['Approval','Email','Webhook','Timer','Condition','IssueCertificate'].forEach(t => sel.add(new Option(t, t)));
  sel.value = step.type;
  sel.onchange = () => {
    updateStepType(step.id, sel.value);
    renderStepsUI({containerEl, addBtnEl, onChange});
    onChange();
  };
  card.appendChild(sel);

  const paramsDiv = document.createElement('div');
  card.appendChild(paramsDiv);

  renderParams(step, paramsDiv, {containerEl, addBtnEl, onChange});
  return card;
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
      { name:'url',    label:'Webhook URL', type:'text' },
      { name:'method', label:'HTTP Method', type:'select', options:['GET','POST','PUT','DELETE'] },
    ],
    Timer: [{ name:'delaySecs', label:'Delay (sec)', type:'number' }],
    Condition: [{ name:'expression', label:'Condition (JS expr)', type:'text' }],
    IssueCertificate: [],
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

// -------- Email step (chips + template/custom) --------
function renderEmailParams(step, container, ctx) {
  const { onChange } = ctx;
  container.textContent = ''; // avoid duplicate blocks

  // Recipients (chips)
  container.appendChild(chipField({
    label: 'Recipients',
    csv: step.params.recipients || '',
    onChange: csv => { updateStepParam(step.id, 'recipients', csv); onChange(); },
  }));

  // From / CC / BCC
  const row = document.createElement('div'); row.className = 'row g-2';
  row.appendChild(colNode(labeledInput('From (optional)', step.params.from_email || '', v => {
    updateStepParam(step.id, 'from_email', v); onChange();
  }, 'email')));
  row.appendChild(colNode(chipField({
    label: 'CC (optional)',
    csv: step.params.cc || '',
    onChange: csv => { updateStepParam(step.id, 'cc', csv); onChange(); },
  })));
  row.appendChild(colNode(chipField({
    label: 'BCC (optional)',
    csv: step.params.bcc || '',
    onChange: csv => { updateStepParam(step.id, 'bcc', csv); onChange(); },
  })));
  container.appendChild(row);

  // Mode: template vs custom
  const useTpl = !!step.params.template;
  const modeWrap = document.createElement('div'); modeWrap.className = 'my-2';
  const tpl = radio('email-mode-'+step.id, 'Use template', useTpl, () => {
    // Switch to template → clear subject/body, ensure a template key
    updateStepParam(step.id, 'subject', '');
    updateStepParam(step.id, 'body', '');
    if (!step.params.template) {
      const first = firstTemplateKey();
      if (first) updateStepParam(step.id, 'template', first);
    }
    renderEmailParams(step, container, ctx); // re-render this section only
    onChange();
  });
  const custom = radio('email-mode-'+step.id, 'Write custom', !useTpl, () => {
    updateStepParam(step.id, 'template', '');
    renderEmailParams(step, container, ctx);
    onChange();
  });
  modeWrap.appendChild(tpl.wrap); modeWrap.appendChild(custom.wrap);
  container.appendChild(modeWrap);

  // Template selectors
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

  // Custom subject/body
  const customBlock = document.createElement('div'); customBlock.className = useTpl ? 'd-none mt-2' : 'mt-2';
  customBlock.appendChild(labeledInput('Subject', step.params.subject || '', v => { updateStepParam(step.id, 'subject', v); onChange(); }));
  customBlock.appendChild(labeledTextArea('Body (plain text)', step.params.body || '', v => { updateStepParam(step.id, 'body', v); onChange(); }));
  container.appendChild(customBlock);

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

// ---- small UI primitives ----
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

// Chips
function chipField({label, csv, onChange}) {
  const lbl = document.createElement('label'); lbl.className = 'form-label small d-block';
  lbl.textContent = label + ': ';
  const holder = document.createElement('div'); holder.className = 'chip-input';
  const input = document.createElement('input'); input.type = 'text'; input.placeholder = 'Type and Enter';
  holder.appendChild(input);
  lbl.appendChild(holder);

  const tokens = [];
  function sync() { onChange(tokens.join(', ')); }
  function addChip(text) {
    const val = (text || '').trim().replace(/,$/, '');
    if (!val) return;
    if (tokens.includes(val)) { input.value = ''; return; }
    tokens.push(val);
    const chip = document.createElement('span'); chip.className = 'chip'; chip.textContent = val;
    const rm = document.createElement('button'); rm.type='button'; rm.className='remove'; rm.innerHTML='&times;';
    rm.onclick = () => { const i = tokens.indexOf(val); if (i>=0) tokens.splice(i,1); chip.remove(); sync(); };
    chip.appendChild(rm);
    holder.insertBefore(chip, input);
    input.value = '';
    sync();
  }
  function seed(csv0) {
    (csv0 || '').split(',').map(s => s.trim()).filter(Boolean).forEach(addChip);
  }
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ',' || e.key === 'Tab') {
      if (input.value.trim() !== '') { e.preventDefault(); addChip(input.value); }
    } else if (e.key === 'Backspace' && input.value === '' && tokens.length) {
      const lastChip = holder.querySelector('.chip:last-of-type');
      if (lastChip) lastChip.querySelector('.remove').click();
    }
  });
  input.addEventListener('blur', () => { if (input.value.trim()) addChip(input.value); });

  seed(csv);
  return lbl;
}
