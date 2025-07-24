// static/js/workflow_wizard.js
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('workflow-wizard');
  if (!container) return;

  // 1) Inject the form skeleton
  container.innerHTML = `
    <form id="wizard-form">
      <div><label>Name: <input type="text" id="wf-name" required></label></div>
      <h3>Trigger</h3>
      <label>Protocol:<select id="trigger-protocol"></select></label>
      <label>Operation:<select id="trigger-operation"></select></label>
      <h3>Steps</h3>
      <button type="button" id="add-step-btn">+ Add Step</button>
      <ul id="steps-list"></ul>
      <h3>Scopes</h3>
      <label>Scope Type:<select id="scope-type">
        <option value="CA">CA</option>
        <option value="Domain">Domain</option>
        <option value="Device">Device</option>
      </select></label>
      <label>Select:<select id="scope-multi" multiple size="4" style="min-width:200px"></select></label>
      <button type="button" id="add-scope-btn">+ Add This Scope</button>
      <ul id="scopes-list"></ul>
      <div style="margin-top:1em"><button type="submit">Save Workflow</button></div>
    </form>
    <pre id="wizard-result" style="color:green;"></pre>
  `;

  // 2) Grab our elements & params
  const wfName      = document.getElementById('wf-name');
  const protoSelect = document.getElementById('trigger-protocol');
  const opSelect    = document.getElementById('trigger-operation');
  const stepsList   = document.getElementById('steps-list');
  const typeSelect  = document.getElementById('scope-type');
  const multiSelect = document.getElementById('scope-multi');
  const scopesList  = document.getElementById('scopes-list');
  const resultPre   = document.getElementById('wizard-result');
  const params      = new URLSearchParams(window.location.search);
  const editId      = params.get('edit');

  // 3) Static step‑type → param definitions
  const stepParamDefs = {
    Approval:   [{name:'approverRole',label:'Approver Role',type:'text'},
                 {name:'timeoutSecs',  label:'Timeout (sec)',  type:'number'}],
    Email:      [{name:'template',   label:'Email Template',type:'text'},
                 {name:'recipients', label:'Recipients (comma)',type:'text'}],
    Webhook:    [{name:'url',        label:'Webhook URL',  type:'text'},
                 {name:'method',     label:'HTTP Method',  type:'select',
                  options:['GET','POST','PUT','DELETE']}],
    Timer:      [{name:'delaySecs',  label:'Delay (sec)',  type:'number'}],
    Condition:  [{name:'expression', label:'Condition (JS expr)',type:'text'}],
    IssueCertificate: []
  };

  // 4) Helper to create elements
  function makeEl(tag, attrs={}, ...kids) {
    const el = document.createElement(tag);
    Object.entries(attrs).forEach(([k,v]) => {
      if (k === 'class') el.className = v;
      else el.setAttribute(k, v);
    });
    kids.forEach(c => el.append(typeof c === 'string' ? document.createTextNode(c) : c));
    return el;
  }

  // 5) Load scope pick‑lists (with Choices.js if available)
  let scopeChoices = null;
  function loadScopeValues() {
    const t = typeSelect.value.toLowerCase();  // "ca", "domain", "device"
    fetch(`/workflows/api/${t}s/`)
      .then(r => r.json())
      .then(items => {
        multiSelect.innerHTML = '';
        items.forEach(it => {
          multiSelect.append(makeEl('option',{value:it.id}, it.name));
        });
        if (scopeChoices) scopeChoices.destroy();
        if (window.Choices) {
          scopeChoices = new Choices(multiSelect, {
            removeItemButton: true,
            placeholder: true,
            placeholderValue: 'Search & select…',
            shouldSort: false
          });
        }
      })
      .catch(err => console.error('Failed to load scopes:', err));
  }
  typeSelect.addEventListener('change', loadScopeValues);
  loadScopeValues();

  // 6) Add a new Step row
  document.getElementById('add-step-btn').addEventListener('click', () => {
    const li = makeEl('li');
    const sel = makeEl('select');
    Object.keys(stepParamDefs).forEach(type => sel.append(makeEl('option',{value:type},type)));
    const paramsDiv = makeEl('div');
    const rm = makeEl('button',{type:'button'},'Remove');
    li.append(
      makeEl('label',{}, 'Type: ', sel),
      paramsDiv,
      rm
    );
    stepsList.append(li);

    function renderParams() {
      paramsDiv.innerHTML = '';
      (stepParamDefs[sel.value]||[]).forEach(def => {
        let inp;
        if (def.type === 'select') {
          inp = makeEl('select',{name:def.name});
          def.options.forEach(opt=>inp.append(makeEl('option',{value:opt},opt)));
        } else {
          inp = makeEl('input',{
            name:def.name,
            type:def.type,
            placeholder:def.label
          });
        }
        paramsDiv.append(
          makeEl('label',{}, def.label+': ', inp),
          makeEl('br')
        );
      });
    }
    sel.addEventListener('change', renderParams);
    renderParams();
    rm.addEventListener('click', () => li.remove());
  });

  // 7) Add a new Scope entry (showing names instead of IDs)
  document.getElementById('add-scope-btn').addEventListener('click', () => {
    const t = typeSelect.value;  // "CA","Domain","Device"
    let items;
    if (scopeChoices) {
      // Choices.js: get full {value,label} objects
      items = scopeChoices.getValue().map(ch => ({value: ch.value, label: ch.label}));
    } else {
      // Plain <select>
      items = Array.from(multiSelect.selectedOptions)
                   .map(o => ({value:o.value, label:o.textContent||o.value}));
    }

    items.forEach(({value:id, label:name}) => {
      // dedupe
      if (scopesList.querySelector(`li[data-scope-type="${t}"][data-scope-id="${id}"]`)) return;
      const li = makeEl(
        'li', {},
        `${t}: ${name} `,
        makeEl('button',{type:'button'}, '✖')
      );
      li.dataset.scopeType = t;
      li.dataset.scopeId   = id;
      li.querySelector('button').addEventListener('click', () => li.remove());
      scopesList.append(li);
    });

    // clear selection
    if (scopeChoices) scopeChoices.clearStore();
    else multiSelect.selectedIndex = -1;
  });

  // 8) Fetch your “single source of truth” triggers & kick off the wizard
  let operationsByProtocol = {};
  fetch('/workflows/api/triggers/')
    .then(r => r.json())
    .then(trigs => {
      operationsByProtocol = trigs;
      populateProtocols();
      updateOps();
      protoSelect.addEventListener('change', updateOps);

      // **now** that protocols & ops exist, load edit‑mode if needed
      if (editId) loadExistingDefinition(editId);
    })
    .catch(err => {
      console.error('Failed to load trigger definitions:', err);
      resultPre.textContent = '⚠️ Could not load trigger definitions';
    });

  function populateProtocols() {
    protoSelect.innerHTML = '';
    Object.keys(operationsByProtocol).forEach(p => {
      protoSelect.append(makeEl('option',{value:p},p));
    });
  }

  function updateOps() {
    opSelect.innerHTML = '';
    (operationsByProtocol[protoSelect.value] || []).forEach(op => {
      opSelect.append(makeEl('option',{value:op},op));
    });
  }

  // 9) Edit‑mode loader
  function loadExistingDefinition(id) {
    fetch(`/workflows/api/definitions/${id}/`)
      .then(r => r.json())
      .then(data => {
        // name
        wfName.value = data.name || '';

        // trigger
        if (data.triggers?.[0]) {
          protoSelect.value = data.triggers[0].protocol;
          updateOps();
          opSelect.value    = data.triggers[0].operation;
        }

        // steps
        data.steps?.forEach(step => {
          document.getElementById('add-step-btn').click(); // create row
          const li = stepsList.lastElementChild;
          const sel = li.querySelector('select');
          sel.value = step.type;
          sel.dispatchEvent(new Event('change')); // render params
          Object.entries(step.params || {}).forEach(([k,v]) => {
            const inp = li.querySelector(`[name="${k}"]`);
            if (inp) inp.value = v;
          });
        });

        // scopes
        data.scopes?.forEach(sc => {
          const li = makeEl(
            'li', {},
            `${sc.type}: ${sc.name} `,
            makeEl('button',{type:'button'}, '✖')
          );
          li.dataset.scopeType = sc.type;
          li.dataset.scopeId   = sc.id;
          li.querySelector('button').addEventListener('click', () => li.remove());
          scopesList.append(li);
        });
      })
      .catch(err => {
        console.error('Failed to load workflow definition:', err);
        resultPre.textContent = `❌ Could not load workflow: ${err}`;
      });
  }

  // 10) Form submission
  document.getElementById('wizard-form').addEventListener('submit', e => {
    e.preventDefault();
    resultPre.textContent = '';

    const name     = wfName.value.trim();
    const triggers = [{protocol: protoSelect.value, operation: opSelect.value}];
    const steps    = Array.from(stepsList.children).map(li => {
      const type = li.querySelector('select').value;
      const params = {};
      li.querySelectorAll('[name]').forEach(inp => {
        params[inp.name] = inp.type==='number' ? Number(inp.value) : inp.value;
      });
      return {type, params};
    });
    const scopes   = Array.from(scopesList.children).map(li => {
      const obj = {ca_id:null, domain_id:null, device_id:null};
      const t = li.dataset.scopeType.toLowerCase();
      obj[`${t}_id`] = li.dataset.scopeId;
      return obj;
    });

    const payload = {name, triggers, steps, scopes};
    if (editId) payload.id = editId;

    fetch('/workflows/wizard/', {
      method: 'POST',
      headers: {
        'Content-Type':'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify(payload),
    })
    .then(async r => {
      const txt = await r.text();
      let data;
      try { data = JSON.parse(txt); }
      catch { data = {error: txt || `Status ${r.status}`} }
      return {status: r.status, data};
    })
    .then(({status,data}) => {
      if (status === 201) {
        resultPre.textContent = `✅ Workflow ID: ${data.id}`;
        window.history.replaceState(null, '', `?edit=${data.id}`);
      } else {
        resultPre.textContent = `❌ ${data.error||JSON.stringify(data)}`;
      }
    })
    .catch(err => {
      resultPre.textContent = `❌ ${err}`;
    });
  });

  // helper to read cookies
  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)'));
    return m ? m.pop() : '';
  }
});
