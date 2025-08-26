// Minimal API helpers (native fetch)

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

export const api = {
  triggers: () => fetchJSON('/workflows/api/triggers/'),
  mailTemplates: () => fetchJSON('/workflows/api/mail-templates/'),
  scopes: (kind) => {
    const k = kind.toLowerCase();
    return fetchJSON(`/workflows/api/${k}s/`);
  },
  definition: (id) => fetchJSON(`/workflows/api/definitions/${id}/`),
  save: async (payload, csrftoken) => {
    const r = await fetch('/workflows/wizard/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrftoken || '',
      },
      body: JSON.stringify(payload),
    });
    const data = await r.json().catch(() => ({}));
    return { ok: r.status === 201, data };
  },
};
