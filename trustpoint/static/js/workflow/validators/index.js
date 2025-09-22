// static/js/workflow/validators/index.js
import { validateEmail } from './email.js';
import { validateWebhook } from './webhook.js';
import { validateApproval } from './approval.js';
import { validateCondition } from './condition.js';

export function validateWizardState(state, triggersMap) {
  const errors = [];

  // name
  if (!state.name || !state.name.trim()) {
    errors.push('Name is required.');
  }

  // trigger selection (condensed, same logic as before)
  const h = (state.handler || '').trim();
  const p = (state.protocol || '').trim();
  const o = (state.operation || '').trim();
  const triples = new Set(Object.values(triggersMap || {}).map(t => [t.handler || '', t.protocol || '', t.operation || ''].join('||')));
  if (!h) errors.push('Event type (handler) is required.');
  else {
    const key = h === 'certificate_request' ? [h, p, o].join('||') : [h, p || '', o || ''].join('||');
    if (h === 'certificate_request' && (!p || !o)) {
      errors.push('Protocol and operation are required for certificate_request.');
    } else if (!triples.has(key)) {
      errors.push('Unknown handler/protocol/operation combination.');
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
      switch (s.type) {
        case 'Email':     validateEmail(s, i, errors); break;
        case 'Webhook':   validateWebhook(s, i, errors); break;
        case 'Approval':  validateApproval(s, i, errors); break;
        case 'Timer':     validateTimer(s, i, errors); break;
        case 'Condition': validateCondition(s, i, errors); break;
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
