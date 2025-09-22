// static/js/workflow/validators/email.js
import { normalizeEmails } from './common.js';

export function validateEmail(step, i, errors) {
  const p = step.params || {};
  const to = normalizeEmails(p.recipients || '');
  if (to.length === 0) errors.push(`Step #${i} (Email): at least one recipient is required.`);
  const hasTpl = !!(p.template || '').trim();
  if (!hasTpl) {
    if (!p.subject || !String(p.subject).trim()) errors.push(`Step #${i} (Email): subject is required in custom mode.`);
    if (!p.body || !String(p.body).trim()) errors.push(`Step #${i} (Email): body is required in custom mode.`);
  }
}
