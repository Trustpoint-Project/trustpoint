// static/js/state.js
// Single source of truth for the wizard.
// NOTE: Sets are used for scopes to keep add/remove cheap and avoid dupes.

export const state = {
  editId: new URLSearchParams(window.location.search).get('edit') || null,

  name: '',
  handler: '',
  protocol: '',
  operation: '',

  steps: [],      // [{ id:number, type:string, params:object }]
  nextStepId: 1,

  scopes: { CA: new Set(), Domain: new Set(), Device: new Set() },

  eventMap: {},                 // GET /workflows/api/events/
  mailTemplates: { groups: [] },   // GET /workflows/api/mail-templates/
  scopesChoices: {
    CA: new Map(), Domain: new Map(), Device: new Map(), // id->name
  },
};

// ---- mutations ----
export function setName(v) {
  state.name = v || '';
}
export function setHandler(h) {
  state.handler = h || '';
  // Selecting a handler invalidates protocol & operation
  state.protocol = '';
  state.operation = '';
}
export function setProtocol(p) {
  state.protocol = p || '';
  // Selecting a protocol invalidates operation
  state.operation = '';
}
export function setOperation(o) {
  state.operation = o || '';
}

export function addStep(type = 'Approval', params = {}) {
  state.steps.push({ id: state.nextStepId++, type, params: { ...params } });
}
export function removeStep(id) {
  state.steps = state.steps.filter(s => s.id !== id);
}
export function updateStepType(id, newType) {
  const s = state.steps.find(x => x.id === id);
  if (!s) return;
  s.type = newType;
  s.params = {}; // reset params when type changes
}
export function updateStepParam(id, key, value) {
  const s = state.steps.find(x => x.id === id);
  if (!s) return;
  s.params[key] = value;
}

/** Move a step to a new index (for drag-and-drop). */
export function moveStep(id, toIndex) {
  const from = state.steps.findIndex(s => s.id === id);
  if (from < 0) return;
  const clamped = Math.max(0, Math.min(toIndex, state.steps.length - 1));
  if (clamped === from) return;
  const [item] = state.steps.splice(from, 1);
  state.steps.splice(clamped, 0, item);
}

export function addScopes(kind, ids) {
  const bucket = state.scopes[kind];
  if (!bucket) return;
  ids.forEach(id => bucket.add(String(id)));
}
export function removeScope(kind, id) {
  const bucket = state.scopes[kind];
  if (!bucket) return;
  bucket.delete(String(id));
}

// ---- payload builder ----
export function buildPayload() {
  const scopesFlat = [
    ...[...state.scopes.CA].map(id => ({ ca_id: id,   domain_id: null, device_id: null })),
    ...[...state.scopes.Domain].map(id => ({ ca_id: null, domain_id: id,  device_id: null })),
    ...[...state.scopes.Device].map(id => ({ ca_id: null, domain_id: null, device_id: id })),
  ];

  return {
    ...(state.editId ? { id: state.editId } : {}),
    name: state.name,
    events: [{
      handler:  state.handler || '',
      protocol: state.protocol || '',
      operation: state.operation || '',
    }],
    steps: state.steps.map(({ type, params }) => {
      if (type === 'Email') {
        // Normalize mutually exclusive params for Email step
        const p = { ...params };
        if (p.template && String(p.template).trim()) {
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
