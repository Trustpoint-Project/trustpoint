// Workflow wizard bootstrapper: deterministic load order + single render path.
import { api } from './api.js';
import { state, setName, buildPayload, addStep } from './state.js';
import { renderEventsUI } from './ui-events.js';
import { renderStepsUI } from './steps.js';
import { initScopesUI } from './scopes.js';
import { renderPreview } from './preview.js';
import { validateWizardState } from './validators.js';
import { renderErrors, clearErrors } from './ui-errors.js';
import { VarPanel } from './var-panel.js';
import { registerTemplatableFields } from './template-fields.js';

// ---------- tiny helpers ----------
const $   = (id) => document.getElementById(id);
const qs  = (k) => new URLSearchParams(window.location.search).get(k);
const getCookie = (name) => (document.cookie.match(new RegExp(`(^| )${name}=([^;]+)`)) || []).pop() || '';

// ---------- DOM refs ----------
const els = {
  handlerEl:      $('event-handler'),
  protoContainer: $('proto-container'),
  opContainer:    $('op-container'),
  protoEl:        $('event-protocol'),
  opEl:           $('event-operation'),

  wfNameEl:       $('wf-name'),

  stepsListEl:    $('steps-list'),
  addStepBtnEl:   $('add-step-btn'),

  scopeTypeEl:    $('scope-type'),
  scopeMultiEl:   $('scope-multi'),
  addScopeBtnEl:  $('add-scope-btn'),
  scopesListEl:   $('scopes-list'),

  previewEl:      $('json-preview'),

  saveDraftBtnEl: $('save-draft-btn'),
  publishBtnEl:   $('publish-btn'),
  saveBtnEl:      $('save-btn'),       // legacy single button

  errorsEl:       $('wizard-errors'),
};

// Ensure an error container exists even if template omitted it.
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

// Called on every mutation to keep preview and var panel in sync
function onAnyChange() {
  clearErrors(els.errorsEl);
  renderPreview(els.previewEl);
  document.dispatchEvent(new CustomEvent('wf:changed'));
}

// ---------- data hydration (one of edit | prefill | empty) ----------
async function hydrateFromDefinition(id) {
  const data = await api.definition(id);

  // name
  state.name = data.name || '';
  if (els.wfNameEl) els.wfNameEl.value = state.name;

  // event
  const tr = (data.events && data.events[0]) || {};
  state.handler   = tr.handler   || '';
  state.protocol  = tr.protocol  || '';
  state.operation = tr.operation || '';

  // steps
  state.steps = [];
  state.nextStepId = 1;
  (data.steps || []).forEach(s => addStep(s.type, s.params || {}));

  // scopes (IDs only; names are display-only)
  state.scopes = { CA: new Set(), Domain: new Set(), Device: new Set() };
  (data.scopes || []).forEach(sc => {
    if (sc.type && sc.id != null && state.scopes[sc.type]) {
      state.scopes[sc.type].add(String(sc.id));
    }
  });
}

async function hydrateFromPrefillIfAny() {
  const pre = await api.prefill().catch(() => ({}));
  if (!pre || !pre.name) {
    return false;
  }

  // name
  state.name = pre.name || '';
  if (els.wfNameEl) els.wfNameEl.value = state.name;

  // event
  const t = (pre.events && pre.events[0]) || {};
  state.handler   = t.handler   || '';
  state.protocol  = t.protocol  || '';
  state.operation = t.operation || '';

  // steps
  state.steps = [];
  state.nextStepId = 1;
  (pre.steps || []).forEach(s => addStep(s.type, s.params || {}));

  // scopes: empty by design on import
  state.scopes = { CA: new Set(), Domain: new Set(), Device: new Set() };

  return true;
}

// Hydrate scopes choice lists (names) if any are pre-selected
async function hydrateScopeChoiceNames() {
  for (const kind of ['CA', 'Domain', 'Device']) {
    if (state.scopes[kind].size && state.scopesChoices[kind].size === 0) {
      try {
        const list = await api.scopes(kind);
        list.forEach(it => state.scopesChoices[kind].set(String(it.id), it.name));
      } catch {
        // non-fatal
      }
    }
  }
}

// ---------- unified render ----------
async function renderAll() {
  // Events (depends on loaded events map)
  renderEventsUI({
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

  // Initial preview
  renderPreview(els.previewEl);
}

// ---------- save wiring ----------
function wireSaveButtons() {
  const doSave = (publishedFlag, buttonEl) => async (ev) => {
    ev?.preventDefault?.();
    if (!buttonEl) return;

    clearErrors(els.errorsEl);

    // optimistic button UX
    const origText = buttonEl.textContent;
    const origDisabled = buttonEl.disabled;
    buttonEl.disabled = true;
    buttonEl.textContent = 'Saving…';

    try {
      const clientErrors = validateWizardState(state, state.eventMap);
      if (clientErrors.length) {
        renderErrors(els.errorsEl, clientErrors);
        return;
      }

      const payload = buildPayload();
      payload.published = !!publishedFlag; // draft=false/publish=true

      const { ok, data } = await api.save(payload, getCookie('csrftoken'));
      if (ok) {
        window.location.href = `/workflows/?saved=${encodeURIComponent(data.id)}`;
        return;
      }
      const serverErrors = Array.isArray(data?.errors)
        ? data.errors
        : [data?.error || data?.message || 'Unknown error'];
      renderErrors(els.errorsEl, serverErrors);
    } catch {
      renderErrors(els.errorsEl, 'Network error while saving. Please try again.');
    } finally {
      buttonEl.disabled = origDisabled;
      buttonEl.textContent = origText;
    }
  };

  // Prefer two-button mode if present; else fallback to single "Save"
  if (els.saveDraftBtnEl || els.publishBtnEl) {
    if (els.saveDraftBtnEl) els.saveDraftBtnEl.onclick = doSave(false, els.saveDraftBtnEl);
    if (els.publishBtnEl)   els.publishBtnEl.onclick   = doSave(true,  els.publishBtnEl);
  } else if (els.saveBtnEl) {
    els.saveBtnEl.type = 'button';
    els.saveBtnEl.onclick = doSave(false, els.saveBtnEl); // legacy = Save Draft
  }
}

// ---------- init (deterministic order) ----------
async function init() {
  // 0) Mount Variables panel first so it can track focus early.
  const varPanel = new VarPanel({ getState: () => state });
  varPanel.mount();

  // 1) Load catalogs (events + mail templates) upfront
  const [trigs, mailTpls] = await Promise.all([
    api.events().catch(() => ({})),
    api.mailTemplates().catch(() => ({ groups: [] })),
  ]);
  state.eventMap   = trigs || {};
  state.mailTemplates = mailTpls && mailTpls.groups ? mailTpls : { groups: [] };

  // 2) Decide data source: edit > prefill > empty
  const editId = qs('edit');
  if (editId) {
    await hydrateFromDefinition(editId);
    await hydrateScopeChoiceNames();
  } else {
    const ok = await hydrateFromPrefillIfAny();
    if (ok) {
      // Nothing else to do; scopes intentionally empty on import
    } else {
      // brand-new empty state (keep defaults)
      state.name = state.name || '';
    }
  }

  // 3) Bind name
  if (els.wfNameEl) {
    els.wfNameEl.oninput = () => { setName(els.wfNameEl.value); onAnyChange(); };
  }

  // 4) Render everything once, after data is hydrated
  await renderAll();

  // 5) Wire save buttons
  wireSaveButtons();

  // 6) Announce initial change for any listeners
  document.dispatchEvent(new CustomEvent('wf:changed'));
}

init().catch(err => console.error('Wizard init failed:', err));
