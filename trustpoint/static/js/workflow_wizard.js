// static/js/workflow_wizard.js
document.addEventListener('DOMContentLoaded', () => {
  const container = document.getElementById('workflow-wizard');
  if (!container) return;

  const operationsByProtocol = {
    EST:   ['simpleenroll'],
    CMP:   ['certRequest'],
    SCEP:  ['enroll', 'renew'],
  };

  const stepParamDefs = {
    Approval: [
      { name: 'approverRole', label: 'Approver Role', type: 'text' },
      { name: 'timeoutSecs',   label: 'Timeout (sec)',  type: 'number' },
    ],
    Email: [
      { name: 'template',   label: 'Email Template',      type: 'text' },
      { name: 'recipients', label: 'Recipients (comma)',  type: 'text' },
    ],
    Webhook: [
      { name: 'url',    label: 'Webhook URL',  type: 'text' },
      {
        name:    'method',
        label:   'HTTP Method',
        type:    'select',
        options: ['GET','POST','PUT','DELETE'],
      },
    ],
    Timer: [
      { name: 'delaySecs', label: 'Delay (sec)', type: 'number' },
    ],
    Condition: [
      { name: 'expression', label: 'Condition (JS expr)', type: 'text' },
    ],
    IssueCertificate: []
  };

  // render the basic form
  container.innerHTML = `
    <form id="wizard-form">
      <div>
        <label>Name:
          <input type="text" id="wf-name" required>
        </label>
      </div>
      <h3>Trigger</h3>
      <label>Protocol:
        <select id="trigger-protocol"></select>
      </label>
      <label>Operation:
        <select id="trigger-operation"></select>
      </label>
      <h3>Steps</h3>
      <button type="button" id="add-step-btn">+ Add Step</button>
      <ul id="steps-list"></ul>
      <h3>Scopes</h3>
      <label>Scope Type:
        <select id="scope-type">
          <option value="CA">CA</option>
          <option value="Domain">Domain</option>
          <option value="Device">Device</option>
        </select>
      </label>
      <label>Select:
        <select id="scope-multi" multiple size="4" style="min-width:200px"></select>
      </label>
      <button type="button" id="add-scope-btn">+ Add This Scope</button>
      <ul id="scopes-list"></ul>
      <div style="margin-top:1em">
        <button type="submit">Save Workflow</button>
      </div>
    </form>
    <pre id="wizard-result" style="color:green;"></pre>
  `;

  // grab our elements
  const protoSelect = document.getElementById('trigger-protocol');
  const opSelect    = document.getElementById('trigger-operation');
  const stepsList   = document.getElementById('steps-list');
  const typeSelect  = document.getElementById('scope-type');
  const multiSelect = document.getElementById('scope-multi');
  const scopesList  = document.getElementById('scopes-list');
  const resultPre   = document.getElementById('wizard-result');
  const params      = new URLSearchParams(window.location.search);
  const editId      = params.get('edit');

  // populate protocol dropdown
  Object.keys(operationsByProtocol).forEach(p => {
    const o = document.createElement('option');
    o.value = p; o.textContent = p;
    protoSelect.append(o);
  });
  function updateOps() {
    opSelect.innerHTML = '';
    (operationsByProtocol[protoSelect.value] || []).forEach(op => {
      const o = document.createElement('option');
      o.value = op; o.textContent = op;
      opSelect.append(o);
    });
  }
  protoSelect.addEventListener('change', updateOps);
  updateOps();

  // load scopes for selected type
  let scopeChoices = null;
  function loadScopeValues() {
    const t = typeSelect.value.toLowerCase();
    fetch(`/workflows/api/${t}s/`)
      .then(r => r.json())
      .then(items => {
        multiSelect.innerHTML = '';
        items.forEach(it => {
          const o = document.createElement('option');
          o.value = it.id; o.textContent = it.name;
          multiSelect.append(o);
        });
        // try Choices.js enhancement if available
        if (window.Choices) {
          if (scopeChoices) scopeChoices.destroy();
          scopeChoices = new Choices(multiSelect, {
            removeItemButton: true,
            placeholder: true,
            placeholderValue: 'Search & select…',
            shouldSort: false,
          });
        }
      });
  }
  typeSelect.addEventListener('change', loadScopeValues);
  loadScopeValues();

  // small helper
  function makeEl(tag, attrs = {}, ...kids) {
    const el = document.createElement(tag);
    Object.entries(attrs).forEach(([k,v])=>{
      if (k==='class') el.className=v; else el.setAttribute(k,v);
    });
    kids.forEach(c => el.append(
      typeof c === 'string' ? document.createTextNode(c) : c
    ));
    return el;
  }

  // add a step row
  document.getElementById('add-step-btn').addEventListener('click', () => {
    const li = makeEl('li');
    const sel = makeEl('select');
    Object.keys(stepParamDefs).forEach(type => {
      sel.append(makeEl('option',{value:type},type));
    });
    const paramsDiv = makeEl('div');
    const rm = makeEl('button',{type:'button'},'Remove');
    li.append(makeEl('label',{},'Type: ', sel), paramsDiv, rm);
    stepsList.append(li);

    function render() {
      paramsDiv.innerHTML = '';
      (stepParamDefs[sel.value]||[]).forEach(d=>{
        let inp;
        if (d.type==='select') {
          inp = makeEl('select',{name:d.name});
          d.options.forEach(opt=>inp.append(makeEl('option',{value:opt},opt)));
        } else {
          inp = makeEl('input',{
            name:d.name, type:d.type, placeholder:d.label
          });
        }
        paramsDiv.append(
          makeEl('label',{}, d.label+': ', inp),
          makeEl('br')
        );
      });
    }
    sel.addEventListener('change', render);
    render();
    rm.addEventListener('click',()=>li.remove());
  });

  // add scope to list
  document.getElementById('add-scope-btn').addEventListener('click', () => {
    const t = typeSelect.value;
    const vals = scopeChoices
      ? scopeChoices.getValue(true)
      : Array.from(multiSelect.selectedOptions).map(o=>o.value);
    vals.forEach(id => {
      if (scopesList.querySelector(`li[data-scope-id="${id}"][data-scope-type="${t}"]`)) {
        return;
      }
      const opt = Array.from(multiSelect.options).find(o=>o.value===id);
      const name = opt ? opt.textContent : id;
      const li = makeEl('li',{}, `${t}: ${name} `,
        makeEl('button',{type:'button'},'✖')
      );
      li.dataset.scopeType = t;
      li.dataset.scopeId   = id;
      li.querySelector('button').addEventListener('click', ()=>li.remove());
      scopesList.append(li);
    });
    if (scopeChoices) scopeChoices.clearStore();
    else multiSelect.selectedIndex = -1;
  });

  // preload when editing
  if (editId) {
    fetch(`/workflows/api/definitions/${editId}/`)
      .then(r => r.json())
      .then(data => {
        document.getElementById('wf-name').value = data.name || '';
        if (data.triggers?.[0]) {
          protoSelect.value = data.triggers[0].protocol;
          updateOps();
          opSelect.value = data.triggers[0].operation;
        }
        data.steps?.forEach(s => addStep(s.type, s.params));
        data.scopes?.forEach(sc => {
          const li = makeEl('li',{},`${sc.type}: ${sc.name} `,
            makeEl('button',{type:'button'},'✖')
          );
          li.dataset.scopeType = sc.type;
          li.dataset.scopeId   = sc.id;
          li.querySelector('button').addEventListener('click',()=>li.remove());
          scopesList.append(li);
        });
      })
      .catch(err => {
        resultPre.textContent = `❌ Could not load workflow: ${err}`;
      });
  }

  // submit handler—redirect on success
  document.getElementById('wizard-form').addEventListener('submit', e => {
    e.preventDefault();
    resultPre.textContent = '';

    const name     = document.getElementById('wf-name').value.trim();
    const triggers = [{ protocol: protoSelect.value, operation: opSelect.value }];
    const steps    = [];
    stepsList.querySelectorAll('li').forEach(li => {
      const type   = li.querySelector('select').value;
      const params = {};
      li.querySelectorAll('[name]').forEach(inp => {
        params[inp.name] = inp.type==='number' ? Number(inp.value) : inp.value;
      });
      steps.push({ type, params });
    });
    const scopes = [];
    scopesList.querySelectorAll('li').forEach(li => {
      const o = { ca_id:null, domain_id:null, device_id:null };
      const t = li.dataset.scopeType.toLowerCase();
      o[`${t}_id`] = li.dataset.scopeId;
      scopes.push(o);
    });

    const payload = { name, triggers, steps, scopes };
    if (editId) payload.id = editId;

    fetch('/workflows/wizard/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken':  getCookie('csrftoken'),
      },
      body: JSON.stringify(payload),
    })
      .then(async r => {
        const txt = await r.text();
        let data;
        try { data = JSON.parse(txt); }
        catch { data = { error: txt||`Status ${r.status}` }; }
        return { status: r.status, data };
      })
      .then(({ status, data }) => {
        if (status === 201) {
          // redirect back to your list, carrying the new‐ID
          window.location.href = `/workflows/?saved=${encodeURIComponent(data.id)}`;
        } else {
          resultPre.textContent = `❌ ${data.error || JSON.stringify(data)}`;
        }
      })
      .catch(err => {
        resultPre.textContent = `❌ ${err}`;
      });
  });

  function getCookie(name) {
    const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)'));
    return m ? m.pop() : '';
  }

  // helper to add a step programmatically
  function addStep(initialType = null, initialParams = {}) {
    document.getElementById('add-step-btn').click(); // reuse the above listener
    const last     = stepsList.lastElementChild;
    const sel      = last.querySelector('select');
    const paramsDiv= last.querySelector('div');
    if (initialType) sel.value = initialType;
    // populate initial params
    Object.entries(initialParams).forEach(([k,v])=>{
      const inp = paramsDiv.querySelector(`[name="${k}"]`);
      if (inp) inp.value = v;
    });
    sel.dispatchEvent(new Event('change'));
  }
});
