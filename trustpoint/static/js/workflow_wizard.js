document.addEventListener('DOMContentLoaded', () => {
  // --- Config ---
  const operationsByProtocol = {
    EST: ['simpleenroll'],
    CMP: ['certRequest'],
    SCEP: ['enroll','renew'],
  };
  const stepParamDefs = {
    Approval: [
      {name:'approverRole', label:'Approver Role', type:'text'},
      {name:'timeoutSecs',   label:'Timeout (sec)',  type:'number'},
    ],
    Email: [
      {name:'template',   label:'Email Template', type:'text'},
      {name:'recipients', label:'Recipients',     type:'text'},
    ],
    Webhook: [
      {name:'url',    label:'Webhook URL', type:'text'},
      {name:'method', label:'HTTP Method', type:'select', options:['GET','POST','PUT','DELETE']},
    ],
    Timer: [
      {name:'delaySecs', label:'Delay (sec)', type:'number'},
    ],
    Condition: [
      {name:'expression', label:'Condition (JS expr)', type:'text'},
    ],
    IssueCertificate: []
  };

  // --- Parse edit ID from URL ---
  const urlParams = new URLSearchParams(window.location.search);
  const editId = urlParams.get('edit');

  // --- DOM refs ---
  const wfNameEl     = document.getElementById('wf-name');
  const protoEl      = document.getElementById('trigger-protocol');
  const opEl         = document.getElementById('trigger-operation');
  const stepsList    = document.getElementById('steps-list');
  const addStepBtn   = document.getElementById('add-step-btn');
  const scopeTypeEl  = document.getElementById('scope-type');
  const multiEl      = document.getElementById('scope-multi');
  const addScopeBtn  = document.getElementById('add-scope-btn');
  const scopesList   = document.getElementById('scopes-list');
  const previewEl    = document.getElementById('json-preview');
  const saveBtn      = document.getElementById('save-btn');

  // --- Helpers ---
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)'));
    return m ? m.pop() : '';
  }

  function regeneratePreview() {
    const name     = wfNameEl.value.trim();
    const triggers = [{ protocol: protoEl.value, operation: opEl.value }];
    const steps    = Array.from(stepsList.children).map(card => {
      const type   = card.querySelector('select.step-type').value;
      const params = {};
      card.querySelectorAll('[data-param-name]').forEach(inp => {
        const key = inp.dataset.paramName;
        const val = inp.type==='number'? Number(inp.value) : inp.value;
        params[key] = val;
      });
      return { type, params };
    });
    const scopes = Array.from(scopesList.children).map(item => {
      const obj = { ca_id:null, domain_id:null, device_id:null };
      const t = item.dataset.scopeType.toLowerCase();
      obj[`${t}_id`] = item.dataset.scopeId;
      return obj;
    });

    const payload = { name, triggers, steps, scopes };
    if (editId) payload.id = editId;
    previewEl.textContent = JSON.stringify(payload, null, 2);
  }

  // --- Populate protocol & operation selects ---
  Object.keys(operationsByProtocol).forEach(p => protoEl.add(new Option(p,p)));
  function updateOperations() {
    opEl.innerHTML = '';
    (operationsByProtocol[protoEl.value]||[]).forEach(o => opEl.add(new Option(o,o)));
    regeneratePreview();
  }
  protoEl.addEventListener('change', updateOperations);
  opEl.addEventListener('change', regeneratePreview);
  updateOperations();
  wfNameEl.addEventListener('input', regeneratePreview);

  // --- Step builder ---
  function addStep(type=null, params={}) {
    const card = document.createElement('div');
    card.className = 'card mb-2 p-2';

    // header + remove
    const hdr = document.createElement('div');
    hdr.className = 'd-flex justify-content-between align-items-center mb-2';
    hdr.innerHTML = '<strong>Step</strong>';
    const rm = document.createElement('button');
    rm.type = 'button'; rm.className = 'btn-close';
    rm.addEventListener('click', () => { card.remove(); regeneratePreview(); });
    hdr.appendChild(rm);
    card.appendChild(hdr);

    // type select
    const sel = document.createElement('select');
    sel.className = 'form-select form-select-sm mb-2 step-type';
    Object.keys(stepParamDefs).forEach(t => sel.add(new Option(t,t)));
    if (type) sel.value = type;
    card.appendChild(sel);

    // params container
    const pd = document.createElement('div');
    card.appendChild(pd);

    function renderParams() {
      pd.innerHTML = '';
      (stepParamDefs[sel.value]||[]).forEach(def => {
        let inp;
        if (def.type==='select') {
          inp = document.createElement('select');
          inp.className = 'form-select form-select-sm mb-1';
          def.options.forEach(o => inp.add(new Option(o,o)));
        } else {
          inp = document.createElement('input');
          inp.type = def.type;
          inp.className = 'form-control form-control-sm mb-1';
        }
        inp.dataset.paramName = def.name;
        inp.placeholder      = def.label;
        if (params[def.name] != null) inp.value = params[def.name];
        inp.addEventListener('input', regeneratePreview);

        const lbl = document.createElement('label');
        lbl.className = 'form-label small';
        lbl.textContent = def.label + ': ';
        lbl.appendChild(inp);
        pd.appendChild(lbl);
      });
      regeneratePreview();
    }

    sel.addEventListener('change', renderParams);
    renderParams();
    sel.addEventListener('change', regeneratePreview);

    stepsList.appendChild(card);
  }

  addStepBtn.addEventListener('click', () => addStep());

  // --- Scopes loader & builder ---
  function loadScopes() {
    const t = scopeTypeEl.value.toLowerCase();
    fetch(`/workflows/api/${t}s/`)
      .then(r=>r.json())
      .then(data=>{
        multiEl.innerHTML = '';
        data.forEach(it => multiEl.add(new Option(it.name, it.id)));
      });
  }
  scopeTypeEl.addEventListener('change', loadScopes);
  loadScopes();

  addScopeBtn.addEventListener('click', () => {
    Array.from(multiEl.selectedOptions).forEach(opt => {
      const div = document.createElement('div');
      div.className = 'alert alert-secondary d-flex justify-content-between align-items-center py-1 px-2';
      div.textContent = `${scopeTypeEl.value}: ${opt.text}`;
      div.dataset.scopeType = scopeTypeEl.value;
      div.dataset.scopeId   = opt.value;
      const rm = document.createElement('button');
      rm.type = 'button'; rm.className = 'btn-close btn-close-sm';
      rm.addEventListener('click', ()=> { div.remove(); regeneratePreview(); });
      div.appendChild(rm);
      scopesList.appendChild(div);
    });
    regeneratePreview();
  });

  // --- Edit-mode preload ---
  if (editId) {
    fetch(`/workflows/api/definitions/${editId}/`)
      .then(r => r.json())
      .then(data => {
        wfNameEl.value = data.name || '';
        if (data.triggers?.[0]) {
          protoEl.value = data.triggers[0].protocol;
          updateOperations();
          opEl.value    = data.triggers[0].operation;
        }
        data.steps?.forEach(s => addStep(s.type, s.params));
        data.scopes?.forEach(sc => {
          const div = document.createElement('div');
          div.className = 'alert alert-secondary d-flex justify-content-between align-items-center py-1 px-2';
          div.textContent = `${sc.type}: ${sc.name}`;
          div.dataset.scopeType = sc.type;
          div.dataset.scopeId   = sc.id;
          const rm = document.createElement('button');
          rm.type = 'button'; rm.className = 'btn-close btn-close-sm';
          rm.addEventListener('click', ()=> { div.remove(); regeneratePreview(); });
          div.appendChild(rm);
          scopesList.appendChild(div);
        });
        regeneratePreview();
      });
  } else {
    // initial preview
    regeneratePreview();
  }

  // --- Save handler ---
  saveBtn.addEventListener('click', () => {
    let payload;
    try {
      payload = JSON.parse(previewEl.textContent);
    } catch {
      return alert('Fix errors before saving.');
    }
    fetch('/workflows/wizard/', {
      method:'POST',
      headers:{
        'Content-Type':'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify(payload),
    })
    .then(async res => {
      const data = await res.json();
      if (res.status === 201) {
        window.location.href = `/workflows/?saved=${data.id}`;
      } else {
        alert('Error: ' + (data.error||'Unknown'));
      }
    });
  });
});
