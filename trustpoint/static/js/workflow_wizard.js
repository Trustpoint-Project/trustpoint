// static/js/workflow_wizard.js
document.addEventListener('DOMContentLoaded', () => {
  // ── Element references ───────────────────────────────────────────────
  const handlerEl     = document.getElementById('trigger-handler');
  const protoContainer= document.getElementById('proto-container');
  const opContainer   = document.getElementById('op-container');
  const protoEl       = document.getElementById('trigger-protocol');
  const opEl          = document.getElementById('trigger-operation');
  const wfNameEl      = document.getElementById('wf-name');
  const stepsList     = document.getElementById('steps-list');
  const addStepBtn    = document.getElementById('add-step-btn');
  const scopeTypeEl   = document.getElementById('scope-type');
  const multiEl       = document.getElementById('scope-multi');
  const addScopeBtn   = document.getElementById('add-scope-btn');
  const scopesList    = document.getElementById('scopes-list');
  const previewEl     = document.getElementById('json-preview');
  const saveBtn       = document.getElementById('save-btn');

  // ── Step parameter definitions ────────────────────────────────────────
  const stepParamDefs = {
    Approval: [
      { name:'approverRole', label:'Approver Role', type:'text' },
      { name:'timeoutSecs',  label:'Timeout (sec)',  type:'number' },
    ],
    Email: [
      { name:'template',   label:'Email Template', type:'text' },
      { name:'recipients', label:'Recipients',     type:'text' },
    ],
    Webhook: [
      { name:'url',    label:'Webhook URL', type:'text' },
      { name:'method', label:'HTTP Method', type:'select', options:['GET','POST','PUT','DELETE'] },
    ],
    Timer: [
      { name:'delaySecs', label:'Delay (sec)', type:'number' },
    ],
    Condition: [
      { name:'expression', label:'Condition (JS expr)', type:'text' },
    ],
    IssueCertificate: []
  };

  // ── State & utilities ─────────────────────────────────────────────────
  let triggersData = {};                         // loaded from API
  const editId     = new URLSearchParams(window.location.search).get('edit');
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)'));
    return m ? m.pop() : '';
  }

  // ── Fetch triggers map ────────────────────────────────────────────────
  fetch('/workflows/api/triggers/')
    .then(r => r.json())
    .then(data => {
      triggersData = data;
      buildHandlerDropdown();
      if (editId) preloadExisting(editId);
      else regeneratePreview();
    })
    .catch(err => {
      console.error('Could not load triggers:', err);
      buildHandlerDropdown();
      regeneratePreview();
    });

  // ── Build Event Type (handler) dropdown ──────────────────────────────
  function buildHandlerDropdown() {
    handlerEl.innerHTML = '';
    // unique handler names
    const handlers = [...new Set(Object.values(triggersData).map(t => t.handler))];
    handlers.forEach(h => {
      // show as normal-case text
      const label = h.replace(/_/g,' ');
      handlerEl.add(new Option(label, h));
    });
    handlerEl.addEventListener('change', onHandlerChange);
    onHandlerChange();
  }

  // ── Handler changed: populate Protocols, then Operations ──────────────
  function onHandlerChange() {
    const h = handlerEl.value;
    // all triggers for this handler
    const relevant = Object.values(triggersData).filter(t => t.handler === h);

    // protocols
    const protocols = [...new Set(relevant.map(t => t.protocol).filter(p => p))];
    if (protocols.length) {
      protoContainer.style.display = '';
      protoEl.innerHTML = '';
      protocols.forEach(p => protoEl.add(new Option(p, p)));
    } else {
      protoContainer.style.display = 'none';
      protoEl.innerHTML = '';
    }

    // now operations
    onProtocolChange();
    regeneratePreview();
  }

  // ── Protocol changed: populate Operations ─────────────────────────────
  protoEl.addEventListener('change', onProtocolChange);
  function onProtocolChange() {
    const h = handlerEl.value;
    const p = protoEl.value;
    const ops = Object.values(triggersData)
      .filter(t => t.handler === h && t.protocol === p)
      .map(t => t.operation)
      .filter(o => o);
    if (ops.length) {
      opContainer.style.display = '';
      opEl.innerHTML = '';
      [...new Set(ops)].forEach(o => opEl.add(new Option(o, o)));
    } else {
      opContainer.style.display = 'none';
      opEl.innerHTML = '';
    }
    regeneratePreview();
  }

  // ── Wire name & operation changes into preview ────────────────────────
  wfNameEl.addEventListener('input', regeneratePreview);
  opEl.addEventListener('change', regeneratePreview);

  // ── STEP builder ──────────────────────────────────────────────────────
  addStepBtn.addEventListener('click', () => addStep());
  function addStep(type = null, params = {}) {
    // card container
    const card = document.createElement('div');
    card.className = 'card mb-2 p-2';

    // header + remove button
    const hdr = document.createElement('div');
    hdr.className = 'd-flex justify-content-between align-items-center mb-2';
    hdr.innerHTML = '<strong>Step</strong>';
    const rm = document.createElement('button');
    rm.type = 'button'; rm.className = 'btn-close';
    rm.onclick = () => { card.remove(); regeneratePreview(); };
    hdr.appendChild(rm);
    card.appendChild(hdr);

    // type select
    const sel = document.createElement('select');
    sel.className = 'form-select form-select-sm mb-2';
    Object.keys(stepParamDefs).forEach(t => sel.add(new Option(t, t)));
    if (type) sel.value = type;
    card.appendChild(sel);

    // params container
    const paramsDiv = document.createElement('div');
    card.appendChild(paramsDiv);

    // renderParams populates paramsDiv & wires inputs
    function renderParams() {
      paramsDiv.innerHTML = '';
      (stepParamDefs[sel.value] || []).forEach(def => {
        let inp;
        if (def.type === 'select') {
          inp = document.createElement('select');
          inp.className = 'form-select form-select-sm mb-1';
          def.options.forEach(o => inp.add(new Option(o, o)));
        } else {
          inp = document.createElement('input');
          inp.type = def.type;
          inp.className = 'form-control form-control-sm mb-1';
        }
        inp.dataset.paramName = def.name;
        inp.placeholder      = def.label;
        if (params[def.name] != null) inp.value = params[def.name];
        inp.oninput = regeneratePreview;

        const lbl = document.createElement('label');
        lbl.className = 'form-label small';
        lbl.textContent = def.label + ': ';
        lbl.appendChild(inp);
        paramsDiv.appendChild(lbl);
      });
    }

    // re-render on type change
    sel.onchange = () => { renderParams(); regeneratePreview(); };
    renderParams();

    // append then preview
    stepsList.appendChild(card);
    regeneratePreview();
  }

  // ── SCOPE builder ─────────────────────────────────────────────────────
  scopeTypeEl.onchange = loadScopes;
  loadScopes();
  function loadScopes() {
    const t = scopeTypeEl.value.toLowerCase();
    fetch(`/workflows/api/${t}s/`)
      .then(r => r.json())
      .then(items => {
        multiEl.innerHTML = '';
        items.forEach(it => multiEl.add(new Option(it.name, it.id)));
      });
  }
  addScopeBtn.onclick = () => {
    Array.from(multiEl.selectedOptions).forEach(opt => {
      const li = document.createElement('li');
      li.className = 'list-group-item d-flex justify-content-between align-items-center';
      li.textContent = `${scopeTypeEl.value}: ${opt.text}`;
      li.dataset.id   = opt.value;
      li.dataset.type = scopeTypeEl.value;
      const rm = document.createElement('button');
      rm.type = 'button'; rm.className = 'btn-close';
      rm.onclick = () => { li.remove(); regeneratePreview(); };
      li.appendChild(rm);
      scopesList.appendChild(li);
    });
    regeneratePreview();
  };

  // ── JSON PREVIEW ──────────────────────────────────────────────────────
  function regeneratePreview() {
    const name   = wfNameEl.value.trim();
    const handler= handlerEl.value;
    const protocol = protoEl.value || '';
    const operation= opEl.value  || '';
    const triggers = [{ handler, protocol, operation }];

    // steps
    const steps = Array.from(stepsList.children).map(card => {
      const type = card.querySelector('select').value;
      const params= {};
      card.querySelectorAll('[data-param-name]').forEach(inp => {
        params[inp.dataset.paramName] =
          inp.type==='number' ? Number(inp.value) : inp.value;
      });
      return { type, params };
    });

    // scopes
    const scopes = [];
    scopesList.querySelectorAll('li').forEach(li => {
      const o = { ca_id:null, domain_id:null, device_id:null };
      o[`${li.dataset.type.toLowerCase()}_id`] = li.dataset.id;
      scopes.push(o);
    });

    const payload = { name, triggers, steps, scopes };
    if (editId) payload.id = editId;
    previewEl.textContent = JSON.stringify(payload, null, 2);
  }

  // ── PRELOAD EXISTING for edit=… ───────────────────────────────────────
  function preloadExisting(id) {
    fetch(`/workflows/api/definitions/${id}/`)
      .then(r => r.json())
      .then(data => {
        wfNameEl.value = data.name || '';

        // find handler by matching protocol+operation
        const { protocol, operation } = data.triggers?.[0] || {};
        const match = Object.entries(triggersData).find(([_,t]) =>
          t.protocol === protocol && t.operation === operation
        );
        if (match) {
          handlerEl.value = match[1].handler;
          onHandlerChange();
          protoEl.value   = protocol;
          onProtocolChange();
          opEl.value      = operation;
        }

        data.steps?.forEach(s => addStep(s.type, s.params));
        data.scopes?.forEach(sc => {
          scopeTypeEl.value = sc.type;
          loadScopes();
          setTimeout(() => {
            Array.from(multiEl.options).forEach(o => {
              if (o.text === sc.name) o.selected = true;
            });
            addScopeBtn.click();
          }, 150);
        });
      });
  }
  if (editId) preloadExisting(editId);

  // ── SAVE ──────────────────────────────────────────────────────────────
  saveBtn.onclick = () => {
    let payload;
    try { payload = JSON.parse(previewEl.textContent); }
    catch { return alert('Fix errors before saving.'); }

    fetch('/workflows/wizard/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken':  getCookie('csrftoken'),
      },
      body: JSON.stringify(payload),
    })
    .then(async r => {
      const data = await r.json();
      if (r.status === 201) {
        window.location.href = `/workflows/?saved=${data.id}`;
      } else {
        alert('Error: ' + (data.error || 'Unknown'));
      }
    })
    .catch(() => {
      alert('Network error while saving.');
    });
  };
});
