// Single source of truth for the wizard

export const state = {
  editId: new URLSearchParams(window.location.search).get('edit') || null,

  name: '',
  handler: '',
  protocol: '',
  operation: '',

  steps: [],      // [{id, type, params}]
  nextStepId: 1,

  scopes: { CA: new Set(), Domain: new Set(), Device: new Set() },

  triggersMap: {},                 // /workflows/api/triggers/
  mailTemplates: { groups: [] },   // /workflows/api/mail-templates/
  scopesChoices: {
    CA: new Map(), Domain: new Map(), Device: new Map(), // id->name
  },
};

// ---- mutations ----
export function setName(v) { state.name = v || ''; }
export function setHandler(h) { state.handler = h || ''; state.protocol=''; state.operation=''; }
export function setProtocol(p) { state.protocol = p || ''; state.operation = ''; }
export function setOperation(o) { state.operation = o || ''; }

export function addStep(type='Approval', params={}) {
  state.steps.push({ id: state.nextStepId++, type, params: { ...params } });
}
export function removeStep(id) {
  state.steps = state.steps.filter(s => s.id !== id);
}
export function updateStepType(id, newType) {
  const s = state.steps.find(x => x.id === id);
  if (!s) return;
  s.type = newType;
  s.params = {};
}
export function updateStepParam(id, key, value) {
  const s = state.steps.find(x => x.id === id);
  if (!s) return;
  s.params[key] = value;
}

export function addScopes(kind, ids) {
  ids.forEach(id => state.scopes[kind].add(String(id)));
}
export function removeScope(kind, id) {
  state.scopes[kind].delete(String(id));
}

// ---- payload builder ----
export function buildPayload() {
  const scopesFlat = [
    ...[...state.scopes.CA].map(id => ({ ca_id:id, domain_id:null, device_id:null })),
    ...[...state.scopes.Domain].map(id => ({ ca_id:null, domain_id:id, device_id:null })),
    ...[...state.scopes.Device].map(id => ({ ca_id:null, domain_id:null, device_id:id })),
  ];

  return {
    ...(state.editId ? { id: state.editId } : {}),
    name: state.name,
    triggers: [{
      handler:  state.handler || '',
      protocol: state.protocol || '',
      operation: state.operation || '',
    }],
    steps: state.steps.map(({type, params}) => {
      if (type === 'Email') {
        const p = { ...params };
        if (p.template) { delete p.subject; delete p.body; }
        else { delete p.template; }
        return { type, params: p };
      }
      return { type, params: { ...params } };
    }),
    scopes: scopesFlat,
  };
}
