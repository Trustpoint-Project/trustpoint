// static/js/workflow/validators/approval.js
import { isPositiveInt } from './common.js';
export function validateApproval(step, i, errors) {
  const p = step.params || {};
  if (p.timeoutSecs != null && !isPositiveInt(p.timeoutSecs)) {
    errors.push(`Step #${i} (Approval): timeoutSecs must be a positive integer if provided.`);
  }
  if (p.approverRole != null && typeof p.approverRole !== 'string') {
    errors.push(`Step #${i} (Approval): approverRole must be a string if provided.`);
  }
}
