// static/js/workflow/api.js
// Minimal API helpers (native fetch, same-origin)

async function fetchJSON(url) {
  const r = await fetch(url, { credentials: 'same-origin' });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

function qs(params) {
  const sp = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v === undefined || v === null) return;
    const s = String(v);
    if (s === '') return;
    sp.set(k, s);
  });
  const q = sp.toString();
  return q ? `?${q}` : '';
}

export const api = {
  events:        () => fetchJSON('/workflows/api/events/'),
  mailTemplates: () => fetchJSON('/workflows/api/mail-templates/'),
  scopes:        (kind) => fetchJSON(`/workflows/api/${kind.toLowerCase()}s/`),

  // Wizard data sources
  definition:    (id) => fetchJSON(`/workflows/api/definitions/${id}/`),
  prefill:       () => fetchJSON('/workflows/api/wizard-prefill/'),

  // NEW: handler-specific variable catalog for wizard panel
  wizardContextCatalog: ({ handler, protocol, operation } = {}) =>
    fetchJSON(`/workflows/api/wizard-context-catalog/${qs({ handler, protocol, operation })}`),

  // Save definition (draft/publish determined by payload.published)
  save: async (payload, csrftoken) => {
    const r = await fetch('/workflows/wizard/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken || '',
      },
      credentials: 'same-origin',
      body: JSON.stringify(payload),
    });
    const data = await r.json().catch(() => ({}));
    return { ok: r.status === 201, data };
  },
};
