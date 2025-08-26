import { api } from './api.js';
import {
  state, setName, buildPayload, addStep,
} from './state.js';
import { renderTriggersUI } from './ui-triggers.js';
import { renderStepsUI } from './steps.js';
import { initScopesUI } from './scopes.js';
import { renderPreview } from './preview.js';

function getCookie(name) {
  const m = document.cookie.match(new RegExp('(^| )'+name+'=([^;]+)'));
  return m ? m.pop() : '';
}

// DOM refs
const els = {
  handlerEl:      document.getElementById('trigger-handler'),
  protoContainer: document.getElementById('proto-container'),
  opContainer:    document.getElementById('op-container'),
  protoEl:        document.getElementById('trigger-protocol'),
  opEl:           document.getElementById('trigger-operation'),
  wfNameEl:       document.getElementById('wf-name'),
  stepsListEl:    document.getElementById('steps-list'),
  addStepBtnEl:   document.getElementById('add-step-btn'),
  scopeTypeEl:    document.getElementById('scope-type'),
  scopeMultiEl:   document.getElementById('scope-multi'),
  addScopeBtnEl:  document.getElementById('add-scope-btn'),
  scopesListEl:   document.getElementById('scopes-list'),
  previewEl:      document.getElementById('json-preview'),
  saveBtnEl:      document.getElementById('save-btn'),
};

function onAnyChange() {
  renderPreview(els.previewEl);
}

async function init() {
  // load catalogs
  const [trigs, mailTpls] = await Promise.all([
    api.triggers().catch(()=> ({})),
    api.mailTemplates().catch(()=> ({ groups: [] })),
  ]);
  state.triggersMap  = trigs || {};
  state.mailTemplates= mailTpls && mailTpls.groups ? mailTpls : { groups: [] };

  // bind name
  els.wfNameEl.oninput = () => { setName(els.wfNameEl.value); onAnyChange(); };

  // triggers UI
  renderTriggersUI({
    els: {
      handlerEl: els.handlerEl,
      protoContainer: els.protoContainer,
      opContainer: els.opContainer,
      protoEl: els.protoEl,
      opEl: els.opEl,
    },
    onChange: onAnyChange,
  });

  // steps UI
  renderStepsUI({
    containerEl: els.stepsListEl,
    addBtnEl: els.addStepBtnEl,
    onChange: onAnyChange,
  });

  // scopes UI
  await initScopesUI({
    typeEl: els.scopeTypeEl,
    multiEl: els.scopeMultiEl,
    addBtnEl: els.addScopeBtnEl,
    listEl: els.scopesListEl,
    onChange: onAnyChange,
  });

  // preload edit
  if (state.editId) {
    const data = await api.definition(state.editId);
    // name
    state.name = data.name || '';
    els.wfNameEl.value = state.name;

    // handler/protocol/operation (infer handler)
    const tr = (data.triggers && data.triggers[0]) || {};
    const match = Object.values(state.triggersMap).find(t => t.protocol === tr.protocol && t.operation === tr.operation);
    state.handler  = (match && match.handler) || '';
    state.protocol = tr.protocol || '';
    state.operation= tr.operation || '';
    renderTriggersUI({
      els: {
        handlerEl: els.handlerEl,
        protoContainer: els.protoContainer,
        opContainer: els.opContainer,
        protoEl: els.protoEl,
        opEl: els.opEl,
      },
      onChange: onAnyChange,
    });

    // steps (reset then add)
    state.steps = [];
    state.nextStepId = 1;
    (data.steps || []).forEach(s => addStep(s.type, s.params || {}));
    renderStepsUI({
      containerEl: els.stepsListEl,
      addBtnEl: els.addStepBtnEl,
      onChange: onAnyChange,
    });

    // scopes
    state.scopes = { CA:new Set(), Domain:new Set(), Device:new Set() };
    (data.scopes || []).forEach(sc => {
      if (sc.type && sc.id != null && state.scopes[sc.type]) {
        state.scopes[sc.type].add(String(sc.id));
      }
    });
    // best-effort cache of names
    for (const kind of ['CA','Domain','Device']) {
      if (state.scopes[kind].size && state.scopesChoices[kind].size === 0) {
        try {
          const list = await api.scopes(kind);
          list.forEach(it => state.scopesChoices[kind].set(String(it.id), it.name));
        } catch {}
      }
    }
    // render scopes list
    await initScopesUI({
      typeEl: els.scopeTypeEl,
      multiEl: els.scopeMultiEl,
      addBtnEl: els.addScopeBtnEl,
      listEl: els.scopesListEl,
      onChange: onAnyChange,
    });
  }

  // initial preview
  renderPreview(els.previewEl);

  // save
  els.saveBtnEl.onclick = async () => {
    const payload = buildPayload();
    const { ok, data } = await api.save(payload, getCookie('csrftoken'));
    if (ok) {
      window.location.href = `/workflows/?saved=${encodeURIComponent(data.id)}`;
    } else {
      alert('Error: ' + (data.error || 'Unknown'));
    }
  };
}

init().catch(err => {
  console.error('Wizard init failed:', err);
});
