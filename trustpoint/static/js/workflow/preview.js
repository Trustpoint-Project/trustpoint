import { buildPayload, state } from './state.js';

function normalizeScopeNames(scopesFlat) {
  // Convert the POST payload scopes (ids) into a preview-friendly representation (names).
  //
  // Output example:
  // {
  //   CA: ["Issuing CA A", "Issuing CA B"],
  //   Domain: ["example.com"],
  //   Device: ["device-01"]
  // }
  const out = { CA: [], Domain: [], Device: [] };

  for (const sc of scopesFlat || []) {
    if (sc.ca_id != null) {
      const id = String(sc.ca_id);
      const name = state.scopesChoices.CA.get(id) || id;
      out.CA.push(name);
    } else if (sc.domain_id != null) {
      const id = String(sc.domain_id);
      const name = state.scopesChoices.Domain.get(id) || id;
      out.Domain.push(name);
    } else if (sc.device_id != null) {
      const id = String(sc.device_id);
      const name = state.scopesChoices.Device.get(id) || id;
      out.Device.push(name);
    }
  }

  // Remove empty keys for readability (optional).
  const compact = {};
  for (const k of Object.keys(out)) {
    if (out[k].length) compact[k] = out[k];
  }
  return compact;
}

function normalizeNumberedSteps(steps) {
  // Convert wizard steps to show stable ids (step-1, step-2, ...) in preview.
  // This mirrors transform_to_definition_schema() on the server.
  return (steps || []).map((s, idx0) => ({
    id: `step-${idx0 + 1}`,
    type: s.type,
    params: s.params || {},
  }));
}

function buildPreviewPayload() {
  // Start from the actual POST payload, then replace only presentation parts.
  const payload = buildPayload();

  return {
    ...(payload.id ? { id: payload.id } : {}),
    name: payload.name,
    events: payload.events,

    // Preview: numbered steps with ids.
    steps: normalizeNumberedSteps(payload.steps),

    // Preview: human-readable scopes grouped by type using names.
    scopes: normalizeScopeNames(payload.scopes),
  };
}

export function renderPreview(preEl) {
  if (!preEl) return;
  const previewPayload = buildPreviewPayload();
  preEl.textContent = JSON.stringify(previewPayload, null, 2);
}
