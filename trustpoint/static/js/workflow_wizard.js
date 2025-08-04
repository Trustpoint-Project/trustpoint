// static/js/workflow_wizard.js

document.addEventListener('DOMContentLoaded', function() {
  var container = document.getElementById('workflow-wizard');
  if (!container) return;

  // 1) Parse the injected STEP_PARAM_DEFS JSON
  var stepParamDefs;
  try {
    stepParamDefs = JSON.parse(
      document.getElementById('stepParamDefs').textContent
    );
    // Expose globally for debugging
    window._stepParamDefs = stepParamDefs;
    console.log('Loaded stepParamDefs:', stepParamDefs);
  } catch (e) {
    console.error('Failed to parse STEP_PARAM_DEFS:', e);
    container.innerHTML = '<p style="color:red;">Error loading step definitions.</p>';
    return;
  }

  // 2) Build the form skeleton
  container.innerHTML = '\
    <form id="wizard-form">\
      <div><label>Name: <input type="text" id="wf-name" required></label></div>\
      <h3>Trigger</h3>\
      <label>Protocol: <select id="trigger-protocol"></select></label>\
      <label>Operation: <select id="trigger-operation"></select></label>\
      <h3>Steps</h3>\
      <button type="button" id="add-step-btn">+ Add Step</button>\
      <ul id="steps-list"></ul>\
      <h3>Scopes</h3>\
      <label>Scope Type: \
        <select id="scope-type">\
          <option value="CA">CA</option>\
          <option value="Domain">Domain</option>\
          <option value="Device">Device</option>\
        </select>\
      </label>\
      <label>Select: <select id="scope-multi" multiple size="4" style="min-width:200px"></select></label>\
      <button type="button" id="add-scope-btn">+ Add This Scope</button>\
      <ul id="scopes-list"></ul>\
      <div style="margin-top:1em"><button type="submit">Save Workflow</button></div>\
    </form>\
    <pre id="wizard-result" style="color:green;"></pre>\
  ';

  // 3) Grab references
  var wfName      = document.getElementById('wf-name');
  var protoSelect = document.getElementById('trigger-protocol');
  var opSelect    = document.getElementById('trigger-operation');
  var stepsList   = document.getElementById('steps-list');
  var typeSelect  = document.getElementById('scope-type');
  var multiSelect = document.getElementById('scope-multi');
  var scopesList  = document.getElementById('scopes-list');
  var resultPre   = document.getElementById('wizard-result');
  var params      = new URLSearchParams(window.location.search);
  var editId      = params.get('edit');

  // 4) Load scopes into the multi-select
  function loadScopeValues() {
    var t = typeSelect.value.toLowerCase();
    fetch('/workflows/api/' + t + 's/')
      .then(function(r){ return r.json(); })
      .then(function(items){
        multiSelect.innerHTML = '';
        items.forEach(function(it){
          var o = document.createElement('option');
          o.value = it.id;
          o.textContent = it.name;
          multiSelect.append(o);
        });
      })
      .catch(function(err){
        console.error('Failed to load scopes:', err);
      });
  }
  typeSelect.addEventListener('change', loadScopeValues);
  loadScopeValues();

  // 5) Load triggers & operations
  var operationsByProtocol = {};
  function populateProtocols() {
    protoSelect.innerHTML = '';
    Object.keys(operationsByProtocol).forEach(function(p){
      var o = document.createElement('option');
      o.value = p;
      o.textContent = p;
      protoSelect.append(o);
    });
  }
  function updateOps() {
    opSelect.innerHTML = '';
    var ops = operationsByProtocol[protoSelect.value] || [];
    ops.forEach(function(op){
      var o = document.createElement('option');
      o.value = op;
      o.textContent = op;
      opSelect.append(o);
    });
  }
  fetch('/workflows/api/triggers/')
    .then(function(r){ return r.json(); })
    .then(function(trigs){
      operationsByProtocol = trigs;
      populateProtocols();
      updateOps();
      protoSelect.addEventListener('change', updateOps);
      if (editId) loadExistingDefinition(editId);
    })
    .catch(function(err){
      console.error('Failed to load trigger definitions:', err);
      resultPre.textContent = '⚠️ Could not load trigger definitions';
    });

  // 6) Add Step button logic
  document.getElementById('add-step-btn').addEventListener('click', function(){
    var li = document.createElement('li');
    var sel = document.createElement('select');
    // Populate Type dropdown
    Object.keys(stepParamDefs).forEach(function(type){
      var o = document.createElement('option');
      o.value = type;
      o.textContent = type;
      sel.append(o);
    });

    var paramsDiv = document.createElement('div');
    var rm = document.createElement('button');
    rm.type = 'button';
    rm.textContent = 'Remove';

    li.appendChild((function(){
      var lbl = document.createElement('label');
      lbl.textContent = 'Type: ';
      return lbl;
    })());
    li.appendChild(sel);
    li.appendChild(paramsDiv);
    li.appendChild(rm);
    stepsList.appendChild(li);

    function renderParams(){
      paramsDiv.innerHTML = '';
      var defs = stepParamDefs[sel.value] || [];
      defs.forEach(function(def){
        var inp;
        if (def.type === 'select') {
        inp = document.createElement('select');
        inp.name = def.name;
        (def.options || []).forEach(function(opt){
            var o = document.createElement('option');
            if (typeof opt === 'object') {
            o.value = opt.value;
            o.textContent = opt.label;
            } else {
            o.value = opt;
            o.textContent = opt;
            }
            inp.appendChild(o);
        });
        } else {
          inp = document.createElement('input');
          inp.type = def.type;
          inp.name = def.name;
          inp.placeholder = def.label;
        }
        var lbl = document.createElement('label');
        lbl.textContent = def.label + ': ';
        lbl.appendChild(inp);
        paramsDiv.appendChild(lbl);
        paramsDiv.appendChild(document.createElement('br'));
      });
    }

    sel.addEventListener('change', renderParams);
    renderParams();
    rm.addEventListener('click', function(){ li.remove(); });
  });

  // 7) Add Scope button logic
  document.getElementById('add-scope-btn').addEventListener('click', function(){
    var items = Array.prototype.slice.call(multiSelect.selectedOptions).map(function(o){
      return { value: o.value, label: o.textContent };
    });
    items.forEach(function(it){
      if (scopesList.querySelector('li[data-scope-id="' + it.value + '"]')) return;
      var li = document.createElement('li');
      li.dataset.scopeType = typeSelect.value;
      li.dataset.scopeId   = it.value;
      li.textContent = typeSelect.value + ': ' + it.label + ' ';
      var x = document.createElement('button');
      x.type = 'button';
      x.textContent = '✖';
      x.addEventListener('click', function(){ li.remove(); });
      li.appendChild(x);
      scopesList.appendChild(li);
    });
    multiSelect.selectedIndex = -1;
  });

  // 8) Load existing workflow for edit
  function loadExistingDefinition(id){
    fetch('/workflows/api/definitions/' + id + '/')
      .then(function(r){ return r.json(); })
      .then(function(data){
        wfName.value = data.name || '';
        if (data.triggers && data.triggers[0]) {
          protoSelect.value = data.triggers[0].protocol;
          updateOps();
          opSelect.value = data.triggers[0].operation;
        }
        if (data.steps) data.steps.forEach(function(step){
          document.getElementById('add-step-btn').click();
          var li = stepsList.lastChild;
          var sel = li.querySelector('select');
          sel.value = step.type;
          sel.dispatchEvent(new Event('change'));
          Object.keys(step.params || {}).forEach(function(k){
            var inp = li.querySelector('[name="' + k + '"]');
            if (inp) inp.value = step.params[k];
          });
        });
        if (data.scopes) data.scopes.forEach(function(sc){
          var li = document.createElement('li');
          li.dataset.scopeType = sc.type;
          li.dataset.scopeId   = sc.id;
          li.textContent = sc.type + ': ' + sc.name + ' ';
          var x = document.createElement('button');
          x.type = 'button';
          x.textContent = '✖';
          x.addEventListener('click', function(){ li.remove(); });
          li.appendChild(x);
          scopesList.appendChild(li);
        });
      })
      .catch(function(err){
        console.error('Failed to load workflow definition:', err);
        resultPre.textContent = '❌ Could not load workflow: ' + err;
      });
  }

  // 9) Form submission
  document.getElementById('wizard-form').addEventListener('submit', function(e){
    e.preventDefault();
    resultPre.textContent = '';

    var name = wfName.value.trim();
    var triggers = [{ protocol: protoSelect.value, operation: opSelect.value }];
    var steps = Array.prototype.slice.call(stepsList.children).map(function(li){
      var type = li.querySelector('select').value;
      var paramsObj = {};
      Array.prototype.slice.call(li.querySelectorAll('[name]')).forEach(function(inp){
        paramsObj[inp.name] = inp.type === 'number' ? Number(inp.value) : inp.value;
      });
      return { type: type, params: paramsObj };
    });
    var scopes = Array.prototype.slice.call(scopesList.children).map(function(li){
      var lower = li.dataset.scopeType.toLowerCase();
      return {
        ca_id:     lower === 'ca'     ? li.dataset.scopeId : null,
        domain_id: lower === 'domain' ? li.dataset.scopeId : null,
        device_id: lower === 'device' ? li.dataset.scopeId : null,
      };
    });

    var payload = { name: name, triggers: triggers, steps: steps, scopes: scopes };
    if (editId) payload.id = editId;

    fetch('/workflows/wizard/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken'),
      },
      body: JSON.stringify(payload),
    })
    .then(function(response){
      return response.text().then(function(txt){
        var data;
        try { data = JSON.parse(txt); }
        catch { data = { error: txt || 'Status ' + response.status }; }
        return { status: response.status, data: data };
      });
    })
    .then(function(res){
      if (res.status === 201) {
        resultPre.textContent = '✅ Workflow ID: ' + res.data.id;
        window.history.replaceState(null, '', '?edit=' + res.data.id);
      } else {
        resultPre.textContent = '❌ ' + (res.data.error || JSON.stringify(res.data));
      }
    })
    .catch(function(err){
      resultPre.textContent = '❌ ' + err;
    });
  });

  // 10) Cookie helper
  function getCookie(name) {
    var m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    return m ? m.pop() : '';
  }
});
