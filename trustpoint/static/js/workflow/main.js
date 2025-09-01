// static/js/main.js
import { api } from './api.js';
import { state, setName, buildPayload, addStep } from './state.js';
import { renderTriggersUI } from './ui-triggers.js';
import { renderStepsUI } from './steps.js';
import { initScopesUI } from './scopes.js';
import { renderPreview } from './preview.js';
import { validateWizardState } from './validators.js';
import { renderErrors, clearErrors } from './ui-errors.js';

function getCookie(name) {
  const m = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
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
  errorsEl:       document.getElementById('wizard-errors'),
};

// If the template forgot the error box, create one just above the preview.
(function ensureErrorContainer() {
  if (!els.errorsEl && els.previewEl && els.previewEl.parentNode) {
    const host = document.createElement('div');
    host.id = 'wizard-errors';
    host.className = 'mb-3 d-none';
    host.setAttribute('aria-live', 'polite');
    host.setAttribute('aria-atomic', 'true');
    els.previewEl.parentNode.insertBefore(host, els.previewEl);
    els.errorsEl = host;
  }
})();

function onAnyChange() {
  clearErrors(els.errorsEl); // clear previous errors on any change
  renderPreview(els.previewEl);
}

async function init() {
  // Load catalogs
  const [trigs, mailTpls] = await Promise.all([
    api.triggers().catch(() => ({})),
    api.mailTemplates().catch(() => ({ groups: [] })),
  ]);
  state.triggersMap   = trigs || {};
  state.mailTemplates = mailTpls && mailTpls.groups ? mailTpls : { groups: [] };

  // Bind name
  els.wfNameEl.oninput = () => { setName(els.wfNameEl.value); onAnyChange(); };

  // Triggers UI
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

  // Steps UI
  renderStepsUI({
    containerEl: els.stepsListEl,
    addBtnEl: els.addStepBtnEl,
    onChange: onAnyChange,
  });

  // Scopes UI
  await initScopesUI({
    typeEl: els.scopeTypeEl,
    multiEl: els.scopeMultiEl,
    addBtnEl: els.addScopeBtnEl,
    listEl: els.scopesListEl,
    onChange: onAnyChange,
  });

  // Preload edit
  if (state.editId) {
    const data = await api.definition(state.editId);

    // Name
    state.name = data.name || '';
    els.wfNameEl.value = state.name;

    // Handler / protocol / operation (infer handler)
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

    // Steps (reset then add)
    state.steps = [];
    state.nextStepId = 1;
    (data.steps || []).forEach(s => addStep(s.type, s.params || {}));
    renderStepsUI({
      containerEl: els.stepsListEl,
      addBtnEl: els.addStepBtnEl,
      onChange: onAnyChange,
    });

    // Scopes
    state.scopes = { CA: new Set(), Domain: new Set(), Device: new Set() };
    (data.scopes || []).forEach(sc => {
      if (sc.type && sc.id != null && state.scopes[sc.type]) {
        state.scopes[sc.type].add(String(sc.id));
      }
    });

    // Best-effort cache of names
    for (const kind of ['CA', 'Domain', 'Device']) {
      if (state.scopes[kind].size && state.scopesChoices[kind].size === 0) {
        try {
          const list = await api.scopes(kind);
          list.forEach(it => state.scopesChoices[kind].set(String(it.id), it.name));
        } catch { /* ignore */ }
      }
    }
    // Re-render scopes list (init re-binds events too)
    await initScopesUI({
      typeEl: els.scopeTypeEl,
      multiEl: els.scopeMultiEl,
      addBtnEl: els.addScopeBtnEl,
      listEl: els.scopesListEl,
      onChange: onAnyChange,
    });
  }

  // Initial preview
  renderPreview(els.previewEl);

  // Save → client-side validate, then server save, then handle server errors
  els.saveBtnEl.onclick = async () => {
    clearErrors(els.errorsEl);

    const clientErrors = validateWizardState(state, state.triggersMap);
    if (clientErrors.length) {
      renderErrors(els.errorsEl, clientErrors);
      return;
    }

    const payload = buildPayload();

    try {
      const { ok, data } = await api.save(payload, getCookie('csrftoken'));
      if (ok) {
        window.location.href = `/workflows/?saved=${encodeURIComponent(data.id)}`;
        return;
      }
      const serverErrors = Array.isArray(data.errors)
        ? data.errors
        : [data.error || data.message || 'Unknown error'];
      renderErrors(els.errorsEl, serverErrors);
    } catch (e) {
      renderErrors(els.errorsEl, 'Network error while saving. Please try again.');
    }
  };
}

init().catch(err => {
  console.error('Wizard init failed:', err);
});
