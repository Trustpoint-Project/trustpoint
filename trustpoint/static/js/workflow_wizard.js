// static/js/workflow_wizard.js
// Single-page workflow wizard with internal state (no DOM scraping).
// - Fixes duplication on edit->save->edit
// - Scopes are Sets (no duplicates)
// - Payload is derived ONLY from state
// - Email step supports Template vs Custom mode (grouped templates if API exists)

document.addEventListener('DOMContentLoaded', () => {
  // ---------- Elements ----------
  const handlerEl      = document.getElementById('trigger-handler');
  const protoContainer = document.getElementById('proto-container');
  const opContainer    = document.getElementById('op-container');
  const protoEl        = document.getElementById('trigger-protocol');
  const opEl           = document.getElementById('trigger-operation');
  const wfNameEl       = document.getElementById('wf-name');

  const stepsList      = document.getElementById('steps-list');
  const addStepBtn     = document.getElementById('add-step-btn');

  const scopeTypeEl    = document.getElementById('scope-type');
  const multiEl        = document.getElementById('scope-multi');
  const addScopeBtn    = document.getElementById('add-scope-btn');
  const scopesList     = document.getElementById('scopes-list');

  const previewEl      = document.getElementById('json-preview');
  const saveBtn        = document.getElementById('save-btn');

  // ---------- Helpers ----------
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? m.pop() : '';
  }
  async function fetchJSON(url) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
    return r.json();
  }
  const editId = new URLSearchParams(window.location.search).get('edit') || null;

  // ---------- State ----------
  const state = {
    editId,
    name: '',
    handler: '',           // e.g. "certificate_request"
    protocol: '',          // e.g. "EST"
    operation: '',         // e.g. "simpleenroll"

    steps: [],             // [{id, type, params:{...}}]
    nextStepId: 1,

    // de-duped scopes
    scopes: { CA: new Set(), Domain: new Set(), Device: new Set() },

    // catalog data
    triggersMap: {},                       // from /workflows/api/triggers/
    mailTemplates: { groups: [] },         // from /workflows/api/mail-templates/
    scopesChoices: {                       // human names for ids (loaded once)
      CA: new Map(),       // id -> name
      Domain: new Map(),
      Device: new Map(),
    },
  };

  // ---------- Param schema for generic steps ----------
  const stepParamDefs = {
    Approval: [
      { name: 'approverRole', label: 'Approver Role', type: 'text' },
      { name: 'timeoutSecs',  label: 'Timeout (sec)',  type: 'number' },
    ],
    Webhook: [
      { name: 'url',    label: 'Webhook URL',  type: 'text' },
      { name: 'method', label: 'HTTP Method',  type: 'select', options: ['GET','POST','PUT','DELETE'] },
    ],
    Timer: [
      { name: 'delaySecs', label: 'Delay (sec)', type: 'number' },
    ],
    Condition: [
      { name: 'expression', label: 'Condition (JS expr)', type: 'text' },
    ],
    IssueCertificate: [],
    // Email is rendered custom
  };

  // ---------- State updaters ----------
  function setName(v) { state.name = v; renderPreview(); }

  function setHandler(h) {
    state.handler = h || '';
    // Reset protocol/op if handler changes
    state.protocol = '';
    state.operation = '';
    renderHandlerProtoOp();
    renderPreview();
  }
  function setProtocol(p) {
    state.protocol = p || '';
    // reset operation when protocol changes
    state.operation = '';
    renderHandlerProtoOp();
    renderPreview();
  }
  function setOperation(o) {
    state.operation = o || '';
    renderPreview();
  }

  function addStep(type = 'Approval', params = {}) {
    state.steps.push({ id: state.nextStepId++, type, params: { ...params } });
    renderSteps();       // only re-render steps area
    renderPreview();
  }
  function removeStep(id) {
    state.steps = state.steps.filter(s => s.id !== id);
    renderSteps();
    renderPreview();
  }
  function updateStepType(id, newType) {
    const s = state.steps.find(x => x.id === id);
    if (!s) return;
    s.type = newType;
    s.params = {}; // reset params when type changes
    renderSteps();
    renderPreview();
  }
  function updateStepParam(id, key, value) {
    const s = state.steps.find(x => x.id === id);
    if (!s) return;
    s.params[key] = value;
    renderPreview();
  }

  function addScopes(kind, ids) {
    ids.forEach(id => state.scopes[kind].add(String(id)));
    renderScopes();
    renderPreview();
  }
  function removeScope(kind, id) {
    state.scopes[kind].delete(String(id));
    renderScopes();
    renderPreview();
  }

  // ---------- Rendering (idempotent, creates fresh content) ----------
  function renderHandlerProtoOp() {
    // Handlers
    handlerEl.innerHTML = '';
    const handlers = [...new Set(Object.values(state.triggersMap).map(t => t.handler))].filter(Boolean);
    handlers.forEach(h => {
      const label = h.replace(/_/g, ' ');            // normal case
      const opt = new Option(label, h);
      if (h === state.handler) opt.selected = true;
      handlerEl.add(opt);
    });
    // If no selection yet, pick first
    if (!state.handler && handlers.length) {
      state.handler = handlers[0];
      handlerEl.value = state.handler;
    }

    // Protocols per handler
    const relevant = Object.values(state.triggersMap).filter(t => t.handler === state.handler);
    const protos   = [...new Set(relevant.map(t => t.protocol).filter(Boolean))];

    if (protos.length) {
      protoContainer.style.display = '';
      protoEl.innerHTML = '';
      protos.forEach(p => {
        const opt = new Option(p, p);
        if (p === state.protocol) opt.selected = true;
        protoEl.add(opt);
      });
      // Default protocol if none chosen
      if (!state.protocol) {
        state.protocol = protos[0];
        protoEl.value = state.protocol;
      }
    } else {
      protoContainer.style.display = 'none';
      protoEl.innerHTML = '';
      state.protocol = '';
    }

    // Operations per (handler, protocol)
    const ops = Object.values(state.triggersMap)
      .filter(t => t.handler === state.handler && t.protocol === state.protocol)
      .map(t => t.operation)
      .filter(Boolean);
    if (ops.length) {
      opContainer.style.display = '';
      opEl.innerHTML = '';
      [...new Set(ops)].forEach(o => {
        const opt = new Option(o, o);
        if (o === state.operation) opt.selected = true;
        opEl.add(opt);
      });
      if (!state.operation) {
        state.operation = ops[0];
        opEl.value = state.operation;
      }
    } else {
      opContainer.style.display = 'none';
      opEl.innerHTML = '';
      state.operation = '';
    }

    // Sync inputs
    handlerEl.value = state.handler || '';
    protoEl.value   = state.protocol || '';
    opEl.value      = state.operation || '';
  }

  function renderSteps() {
    // Rebuild steps area completely from state
    stepsList.textContent = '';
    const frag = document.createDocumentFragment();
    state.steps.forEach(step => frag.appendChild(renderStepCard(step)));
    stepsList.appendChild(frag);
  }

  function renderStepCard(step) {
    const card = document.createElement('div');
    card.className = 'card mb-2 p-2';

    const header = document.createElement('div');
    header.className = 'd-flex justify-content-between align-items-center mb-2';
    header.innerHTML = `<strong>Step</strong>`;
    const rm = document.createElement('button');
    rm.type = 'button';
    rm.className = 'btn-close';
    rm.addEventListener('click', () => removeStep(step.id));
    header.appendChild(rm);
    card.appendChild(header);

    // Type selector
    const typeSel = document.createElement('select');
    typeSel.className = 'form-select form-select-sm mb-2';
    const types = ['Approval', 'Email', 'Webhook', 'Timer', 'Condition', 'IssueCertificate'];
    types.forEach(t => typeSel.add(new Option(t, t)));
    typeSel.value = step.type;
    typeSel.addEventListener('change', () => updateStepType(step.id, typeSel.value));
    card.appendChild(typeSel);

    // Params container
    const paramsDiv = document.createElement('div');
    card.appendChild(paramsDiv);

    // Render params according to type
    if (step.type === 'Email') {
      renderEmailParams(paramsDiv, step);
    } else {
      (stepParamDefs[step.type] || []).forEach(def => {
        const lbl = document.createElement('label');
        lbl.className = 'form-label small d-block';
        lbl.textContent = def.label + ': ';

        let inp;
        if (def.type === 'select') {
          inp = document.createElement('select');
          inp.className = 'form-select form-select-sm';
          def.options.forEach(o => inp.add(new Option(o, o)));
        } else {
          inp = document.createElement('input');
          inp.type = def.type;
          inp.className = 'form-control form-control-sm';
        }
        inp.value = step.params[def.name] ?? '';
        inp.addEventListener('input', () => {
          const v = def.type === 'number' ? Number(inp.value || 0) : inp.value;
          updateStepParam(step.id, def.name, v);
        });

        lbl.appendChild(inp);
        paramsDiv.appendChild(lbl);
      });
    }

    return card;
  }

  function renderEmailParams(container, step) {
    // Addresses (recipients / cc / bcc / from)
    const addrRow = document.createElement('div');
    addrRow.className = 'row g-2';

    // Recipients
    const colTo = document.createElement('div'); colTo.className = 'col-md-6';
    colTo.appendChild(labeledTextArea('Recipients (comma-separated)', step.params.recipients || '', v => {
      updateStepParam(step.id, 'recipients', v);
    }));
    addrRow.appendChild(colTo);

    // From
    const colFrom = document.createElement('div'); colFrom.className = 'col-md-6';
    colFrom.appendChild(labeledInput('From (optional)', step.params.from_email || '', v => {
      updateStepParam(step.id, 'from_email', v);
    }, 'email'));
    addrRow.appendChild(colFrom);

    // CC/BCC
    const row2 = document.createElement('div');
    row2.className = 'row g-2 mt-1';
    const colCc = document.createElement('div'); colCc.className = 'col-md-6';
    colCc.appendChild(labeledInput('CC (optional, comma-separated)', step.params.cc || '', v => {
      updateStepParam(step.id, 'cc', v);
    }));
    const colBcc = document.createElement('div'); colBcc.className = 'col-md-6';
    colBcc.appendChild(labeledInput('BCC (optional, comma-separated)', step.params.bcc || '', v => {
      updateStepParam(step.id, 'bcc', v);
    }));
    row2.appendChild(colCc);
    row2.appendChild(colBcc);

    container.appendChild(addrRow);
    container.appendChild(row2);

    // Content mode: Template vs Custom
    const modeWrap = document.createElement('div');
    modeWrap.className = 'mt-2';

    const useTemplate = !!step.params.template;
    const templateRb = radio('email-mode-' + step.id, 'Use template', useTemplate, () => {
      // switch to template mode: clear custom fields
      updateStepParam(step.id, 'subject', '');
      updateStepParam(step.id, 'body', '');
      // if no template set yet, auto-pick first available
      if (!step.params.template) {
        const first = firstTemplateKey();
        if (first) updateStepParam(step.id, 'template', first);
      }
      renderSteps(); // re-render this card to reflect visibility
    });
    const customRb = radio('email-mode-' + step.id, 'Write custom', !useTemplate, () => {
      // switch to custom mode: clear template
      updateStepParam(step.id, 'template', '');
      renderSteps();
    });
    modeWrap.appendChild(templateRb.wrap);
    modeWrap.appendChild(customRb.wrap);
    container.appendChild(modeWrap);

    // Template selects (group + template)
    const tplBlock = document.createElement('div');
    tplBlock.className = useTemplate ? '' : 'd-none';

    const tplRow = document.createElement('div');
    tplRow.className = 'row g-2 mt-1';

    const colGroup = document.createElement('div'); colGroup.className = 'col-md-6';
    const colTpl   = document.createElement('div'); colTpl.className = 'col-md-6';

    const groupSel = document.createElement('select');
    groupSel.className = 'form-select form-select-sm';

    const tplSel = document.createElement('select');
    tplSel.className = 'form-select form-select-sm';

    // Fill groups
    const groups = (state.mailTemplates && Array.isArray(state.mailTemplates.groups)) ? state.mailTemplates.groups : [];
    groupSel.innerHTML = '';
    groups.forEach(g => groupSel.add(new Option(g.label || g.key, g.key)));

    // pick current group based on selected template, else first
    const currentTplKey = step.params.template || '';
    const currentGroupKey = findGroupKeyForTemplate(currentTplKey) || (groups[0]?.key || '');
    groupSel.value = currentGroupKey;

    // Fill templates for group
    fillTemplatesForGroup(currentGroupKey, tplSel);
    if (currentTplKey && [...tplSel.options].some(o => o.value === currentTplKey)) {
      tplSel.value = currentTplKey;
    }

    groupSel.addEventListener('change', () => {
      fillTemplatesForGroup(groupSel.value, tplSel);
      // pick first template
      const chosen = tplSel.value || '';
      updateStepParam(step.id, 'template', chosen);
      renderPreview();
    });
    tplSel.addEventListener('change', () => {
      updateStepParam(step.id, 'template', tplSel.value || '');
      renderPreview();
    });

    colGroup.appendChild(labeledNode('Template group', groupSel));
    colTpl.appendChild(labeledNode('Template', tplSel));
    tplRow.appendChild(colGroup);
    tplRow.appendChild(colTpl);
    tplBlock.appendChild(tplRow);
    container.appendChild(tplBlock);

    // Custom subject/body
    const customBlock = document.createElement('div');
    customBlock.className = useTemplate ? 'd-none mt-2' : 'mt-2';
    customBlock.appendChild(labeledInput('Subject', step.params.subject || '', v => {
      updateStepParam(step.id, 'subject', v);
    }));
    const bodyLabel = document.createElement('label');
    bodyLabel.className = 'form-label small d-block';
    bodyLabel.textContent = 'Body (plain text): ';
    const bodyArea = document.createElement('textarea');
    bodyArea.className = 'form-control form-control-sm';
    bodyArea.rows = 5;
    bodyArea.value = step.params.body || '';
    bodyArea.addEventListener('input', () => updateStepParam(step.id, 'body', bodyArea.value));
    bodyLabel.appendChild(bodyArea);
    customBlock.appendChild(bodyLabel);
    container.appendChild(customBlock);

    // utilities (local)
    function firstTemplateKey() {
      const gg = state.mailTemplates?.groups || [];
      for (const g of gg) {
        if (g.templates && g.templates.length) return g.templates[0].key;
      }
      return '';
    }
    function findGroupKeyForTemplate(tplKey) {
      const gg = state.mailTemplates?.groups || [];
      for (const g of gg) {
        if ((g.templates || []).some(t => t.key === tplKey)) return g.key;
      }
      return '';
    }
    function fillTemplatesForGroup(groupKey, sel) {
      sel.innerHTML = '';
      const g = (state.mailTemplates?.groups || []).find(x => x.key === groupKey);
      (g?.templates || []).forEach(t => sel.add(new Option(t.label || t.key, t.key)));
      if (!sel.value && sel.options.length) sel.selectedIndex = 0;
    }
  }

  function labeledInput(labelText, value, onInput, type = 'text') {
    const lbl = document.createElement('label');
    lbl.className = 'form-label small d-block';
    lbl.textContent = labelText + ': ';
    const inp = document.createElement('input');
    inp.className = 'form-control form-control-sm';
    inp.type = type;
    inp.value = value || '';
    inp.addEventListener('input', () => onInput(inp.value));
    lbl.appendChild(inp);
    return lbl;
  }
  function labeledTextArea(labelText, value, onInput) {
    const lbl = document.createElement('label');
    lbl.className = 'form-label small d-block';
    lbl.textContent = labelText + ': ';
    const ta = document.createElement('textarea');
    ta.className = 'form-control form-control-sm';
    ta.rows = 3;
    ta.value = value || '';
    ta.addEventListener('input', () => onInput(ta.value));
    lbl.appendChild(ta);
    return lbl;
  }
  function labeledNode(labelText, node) {
    const lbl = document.createElement('label');
    lbl.className = 'form-label small d-block';
    lbl.textContent = labelText + ': ';
    lbl.appendChild(node);
    return lbl;
  }
  function radio(name, label, checked, onChange) {
    const id = `${name}-${Math.random().toString(36).slice(2, 8)}`;
    const wrap = document.createElement('div');
    wrap.className = 'form-check form-check-inline';
    const input = document.createElement('input');
    input.className = 'form-check-input';
    input.type = 'radio';
    input.name = name;
    input.id = id;
    input.checked = !!checked;
    input.addEventListener('change', onChange);
    const lab = document.createElement('label');
    lab.className = 'form-check-label';
    lab.setAttribute('for', id);
    lab.textContent = label;
    wrap.appendChild(input);
    wrap.appendChild(lab);
    return { wrap, input };
  }

  function renderScopes() {
    scopesList.textContent = '';
    const frag = document.createDocumentFragment();
    for (const kind of ['CA', 'Domain', 'Device']) {
      for (const id of state.scopes[kind]) {
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex justify-content-between align-items-center';
        const name = state.scopesChoices[kind].get(String(id)) || String(id);
        li.textContent = `${kind}: ${name}`;
        const rm = document.createElement('button');
        rm.type = 'button';
        rm.className = 'btn-close';
        rm.addEventListener('click', () => removeScope(kind, id));
        li.appendChild(rm);
        frag.appendChild(li);
      }
    }
    scopesList.appendChild(frag);
  }

  function renderPreview() {
    const payload = buildPayloadFromState();
    previewEl.textContent = JSON.stringify(payload, null, 2);
  }

  function buildPayloadFromState() {
    const scopesFlat = [
      ...[...state.scopes.CA].map(id => ({ ca_id: id,     domain_id: null, device_id: null })),
      ...[...state.scopes.Domain].map(id => ({ ca_id: null, domain_id: id,  device_id: null })),
      ...[...state.scopes.Device].map(id => ({ ca_id: null, domain_id: null, device_id: id })),
    ];
    return {
      ...(state.editId ? { id: state.editId } : {}),
      name: state.name,
      triggers: [{
        handler: state.handler || '',
        protocol: state.protocol || '',
        operation: state.operation || '',
      }],
      steps: state.steps.map(({ type, params }) => {
        // Email exclusivity: if template set, drop subject/body; if not, drop template
        if (type === 'Email') {
          const p = { ...params };
          if (p.template) {
            delete p.subject;
            delete p.body;
          } else {
            delete p.template;
          }
          return { type, params: p };
        }
        return { type, params: { ...params } };
      }),
      scopes: scopesFlat,
    };
  }

  // ---------- Wire static events ----------
  wfNameEl.addEventListener('input', () => setName(wfNameEl.value));
  handlerEl.addEventListener('change', () => setHandler(handlerEl.value));
  protoEl.addEventListener('change', () => setProtocol(protoEl.value));
  opEl.addEventListener('change',     () => setOperation(opEl.value));

  addStepBtn.addEventListener('click', () => addStep());

  scopeTypeEl.addEventListener('change', loadScopeChoicesForCurrentType);
  addScopeBtn.addEventListener('click', () => {
    const kind = scopeTypeEl.value;
    const ids  = Array.from(multiEl.selectedOptions).map(o => o.value);
    addScopes(kind, ids);
    multiEl.selectedIndex = -1;
  });

  saveBtn.addEventListener('click', async () => {
    try {
      const payload = buildPayloadFromState();
      const r = await fetch('/workflows/wizard/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken'),
        },
        body: JSON.stringify(payload),
      });
      const data = await r.json();
      if (r.status === 201) {
        window.location.href = `/workflows/?saved=${encodeURIComponent(data.id)}`;
      } else {
        alert('Error: ' + (data.error || 'Unknown'));
      }
    } catch (e) {
      console.error(e);
      alert('Network error while saving.');
    }
  });

  // ---------- Data loading ----------
  async function loadInitialData() {
    try {
      const [trigs, mtpls, cas, doms, devs] = await Promise.all([
        fetchJSON('/workflows/api/triggers/').catch(() => ({})),
        fetchJSON('/workflows/api/mail-templates/').catch(() => ({ groups: [] })),
        fetchJSON('/workflows/api/cas/').catch(() => []),
        fetchJSON('/workflows/api/domains/').catch(() => []),
        fetchJSON('/workflows/api/devices/').catch(() => []),
      ]);
      state.triggersMap  = trigs || {};
      state.mailTemplates = (mtpls && mtpls.groups) ? mtpls : { groups: [] };
      (cas || []).forEach(c  => state.scopesChoices.CA.set(String(c.id), c.name));
      (doms || []).forEach(d => state.scopesChoices.Domain.set(String(d.id), d.name));
      (devs || []).forEach(d => state.scopesChoices.Device.set(String(d.id), d.name));

      renderHandlerProtoOp();
      renderScopes();   // empty initially (but names ready)
      if (state.editId) await preloadExisting(state.editId);
      renderPreview();
    } catch (e) {
      console.error('Initialization failed:', e);
      // still render empty UI
      renderHandlerProtoOp();
      renderScopes();
      renderPreview();
    }
  }

  async function preloadExisting(id) {
    const data = await fetchJSON(`/workflows/api/definitions/${id}/`);
    state.name = data.name || '';
    wfNameEl.value = state.name;

    const tr = (data.triggers && data.triggers[0]) || {};
    // infer handler by protocol+operation
    const match = Object.values(state.triggersMap).find(t => t.protocol === tr.protocol && t.operation === tr.operation);
    state.handler  = (match && match.handler) || '';
    state.protocol = tr.protocol || '';
    state.operation= tr.operation || '';
    renderHandlerProtoOp();

    // steps
    state.steps = [];
    state.nextStepId = 1;
    (data.steps || []).forEach(s => addStep(s.type, s.params || {})); // addStep updates render+preview

    // scopes -> Sets
    state.scopes = { CA: new Set(), Domain: new Set(), Device: new Set() };
    (data.scopes || []).forEach(sc => {
      if (sc.type && sc.id != null && state.scopes[sc.type]) {
        state.scopes[sc.type].add(String(sc.id));
      }
    });
    renderScopes();
    renderPreview();
  }

  async function loadScopeChoicesForCurrentType() {
    // Keep the three lists cached; also repopulate the multi select for the chosen type
    const type = scopeTypeEl.value;
    if (!['CA','Domain','Device'].includes(type)) return;

    let list = [];
    try {
      if (type === 'CA')      list = await fetchJSON('/workflows/api/cas/');
      if (type === 'Domain')  list = await fetchJSON('/workflows/api/domains/');
      if (type === 'Device')  list = await fetchJSON('/workflows/api/devices/');
    } catch { list = []; }

    // cache names
    list.forEach(it => state.scopesChoices[type].set(String(it.id), it.name));

    // fill the select
    multiEl.innerHTML = '';
    list.forEach(it => multiEl.add(new Option(it.name, it.id)));
  }

  // ---------- Kickoff ----------
  loadInitialData();
});
