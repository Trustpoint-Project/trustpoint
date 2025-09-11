// static/js/workflow/validators/condition.js
export function validateCondition(step, i, errors) {
  const p = step.params || {};
  if (!(typeof p.expression === 'string' && p.expression.trim())) {
    errors.push(`Step #${i} (Condition): expression is required (string).`);
  }
}