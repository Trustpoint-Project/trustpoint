// static/js/workflow/main.js
import { api } from './api.js';
import { state, setName, buildPayload, addStep } from './state.js';
import { renderTriggersUI } from './ui-triggers.js';
import { renderStepsUI } from './steps.js';
import { initScopesUI } from './scopes.js';
import { renderPreview } from './preview.js';
import { validateWizardState } from './validators.js';
import { renderErrors, clearErrors } from './ui-errors.js';
import { VarPanel } from './var-panel.js';
import { registerTemplatableFields } from './template-fields.js';

function $(id) { return document.getElementById(id); }
function getCookie(name) {
  const m = document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`));
  return m ? m.pop() : '';
}

// DOM refs
const els = {
  handlerEl:      $('trigger-handler'),
  protoContainer: $('proto-container'),
  opContainer:    $('op-container'),
  protoEl:        $('trigger-protocol'),
  opEl:           $('trigger-operation'),
  wfNameEl:       $('wf-name'),
  stepsListEl:    $('steps-list'),
  addStepBtnEl:   $('add-step-btn'),
  scopeTypeEl:    $('scope-type'),
  scopeMultiEl:   $('scope-multi'),
  addScopeBtnEl:  $('add-scope-btn'),
  scopesListEl:   $('scopes-list'),
  previewEl:      $('json-preview'),
  saveBtnEl:      $('save-btn'),
  errorsEl:       $('wizard-errors'),
};

// Ensure an error container exists (non-breaking if template omitted it).
(function ensureErrorContainer() {
  if (!els.errorsEl && els.previewEl?.parentNode) {
    const host = document.createElement('div');
    host.id = 'wizard-errors';
    host.className = 'mb-3 d-none';
    host.setAttribute('aria-live', 'polite');
    host.setAttribute('aria-atomic', 'true');
    els.previewEl.parentNode.insertBefore(host, els.previewEl);
    els.errorsEl = host;
  }
}());

function onAnyChange() {
  clearErrors(els.errorsEl);
  renderPreview(els.previewEl);
  // notify var panel & any listeners
  document.dispatchEvent(new CustomEvent('wf:changed'));
}

async function preloadEditIfAny() {
  if (!state.editId) return;

  const data = await api.definition(state.editId);

  // name
  state.name = data.name || '';
  els.wfNameEl.value = state.name;

  // handler/protocol/operation
  const tr = (data.triggers && data.triggers[0]) || {};
  const match = Object.values(state.triggersMap).find(
    t => t.protocol === tr.protocol && t.operation === tr.operation
  );
  state.handler   = (match && match.handler) || '';
  state.protocol  = tr.protocol || '';
  state.operation = tr.operation || '';

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

  // steps
  state.steps = [];
  state.nextStepId = 1;
  (data.steps || []).forEach(s => addStep(s.type, s.params || {}));
  renderStepsUI({
    containerEl: els.stepsListEl,
    addBtnEl: els.addStepBtnEl,
    onChange: () => { onAnyChange(); registerTemplatableFields(els.stepsListEl); },
  });
  registerTemplatableFields(els.stepsListEl);

  // scopes
  state.scopes = { CA: new Set(), Domain: new Set(), Device: new Set() };
  (data.scopes || []).forEach(sc => {
    if (sc.type && sc.id != null && state.scopes[sc.type]) {
      state.scopes[sc.type].add(String(sc.id));
    }
  });

  // hydrate names if needed, then re-init scopes list
  for (const kind of ['CA', 'Domain', 'Device']) {
    if (state.scopes[kind].size && state.scopesChoices[kind].size === 0) {
      try {
        const list = await api.scopes(kind);
        list.forEach(it => state.scopesChoices[kind].set(String(it.id), it.name));
      } catch { /* ignore */ }
    }
  }
  await initScopesUI({
    typeEl: els.scopeTypeEl,
    multiEl: els.scopeMultiEl,
    addBtnEl: els.addScopeBtnEl,
    listEl: els.scopesListEl,
    onChange: onAnyChange,
  });

  // one shot notify post-preload
  document.dispatchEvent(new CustomEvent('wf:changed'));
}

async function init() {
  // Mount Variables panel (Ctrl/Cmd+K) first so it can track focus immediately.
  const varPanel = new VarPanel({ getState: () => state });
  varPanel.mount();

  // Load catalogs
  const [trigs, mailTpls] = await Promise.all([
    api.triggers().catch(() => ({})),
    api.mailTemplates().catch(() => ({ groups: [] })),
  ]);
  state.triggersMap   = trigs || {};
  state.mailTemplates = mailTpls && mailTpls.groups ? mailTpls : { groups: [] };

  // Bind name
  els.wfNameEl.oninput = () => { setName(els.wfNameEl.value); onAnyChange(); };

  // Triggers
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

  // Steps
  renderStepsUI({
    containerEl: els.stepsListEl,
    addBtnEl: els.addStepBtnEl,
    onChange: () => { onAnyChange(); registerTemplatableFields(els.stepsListEl); },
  });
  registerTemplatableFields(els.stepsListEl);

  // Scopes
  await initScopesUI({
    typeEl: els.scopeTypeEl,
    multiEl: els.scopeMultiEl,
    addBtnEl: els.addScopeBtnEl,
    listEl: els.scopesListEl,
    onChange: onAnyChange,
  });

  // Preload edit if query has ?edit=...
  await preloadEditIfAny();

  // Initial preview
  renderPreview(els.previewEl);
}

init().catch(err => console.error('Wizard init failed:', err));
