// static/js/validators.js
// Client-side validator mirroring the server rules.

function normalizeEmails(value) {
  if (!value) return [];
  const parts = Array.isArray(value)
    ? value.map(String)
    : String(value).split(',');
  return parts.map(s => s.trim()).filter(Boolean);
}

function knownTriples(triggersMap) {
  // Build set of (handler, protocol, operation) from the API map.
  const set = new Set();
  Object.values(triggersMap || {}).forEach(t => {
    const h = (t.handler || '').trim();
    const p = (t.protocol || '').trim();
    const o = (t.operation || '').trim();
    set.add([h, p, o].join('||'));
    // allow empty p/o for non-certificate handlers (defensive)
    if (!p && !o) set.add([h, '', ''].join('||'));
  });
  return set;
}

export function validateWizardState(state, triggersMap) {
  const errors = [];

  // name
  if (!state.name || !state.name.trim()) {
    errors.push('Name is required.');
  }

  // trigger (we only support single trigger in UI)
  const h = (state.handler || '').trim();
  const p = (state.protocol || '').trim();
  const o = (state.operation || '').trim();
  if (!h) {
    errors.push('Event type (handler) is required.');
  } else {
    const triples = knownTriples(triggersMap);
    if (h === 'certificate_request') {
      if (!p || !o) {
        errors.push('Protocol and operation are required for certificate_request.');
      } else if (!triples.has([h, p, o].join('||'))) {
        errors.push('Unknown handler/protocol/operation combination.');
      }
    } else {
      // non-certificate: allow empty p/o
      const key = [h, p || '', o || ''].join('||');
      if (!triples.has(key)) {
        errors.push('Unknown event type selection.');
      }
    }
  }

  // steps
  const allowed = new Set(['Approval', 'Email', 'Webhook', 'Timer', 'Condition']);
  if (!Array.isArray(state.steps) || state.steps.length === 0) {
    errors.push('At least one step is required.');
  } else {
    state.steps.forEach((s, idx) => {
      const i = idx + 1;
      if (!allowed.has(s.type)) {
        errors.push(`Step #${i}: unknown type "${s.type}".`);
        return;
      }
      const params = s.params || {};
      if (s.type === 'Email') {
        const to = normalizeEmails(params.recipients || '');
        if (to.length === 0) {
          errors.push(`Step #${i} (Email): at least one recipient is required.`);
        }
        const hasTpl = !!(params.template || '').trim();
        if (!hasTpl) {
          if (!params.subject || !String(params.subject).trim()) {
            errors.push(`Step #${i} (Email): subject is required in custom mode.`);
          }
          if (!params.body || !String(params.body).trim()) {
            errors.push(`Step #${i} (Email): body is required in custom mode.`);
          }
        }
      }
    });
  }

  // scopes
  const scopeCount =
    (state.scopes.CA?.size || 0) +
    (state.scopes.Domain?.size || 0) +
    (state.scopes.Device?.size || 0);
  if (scopeCount === 0) {
    errors.push('At least one scope (CA/Domain/Device) is required.');
  }

  return errors;
}
