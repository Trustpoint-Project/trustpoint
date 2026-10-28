import { uniqStrings } from '../shared/utils.js';

export function findStepSpec(catalog, stepType) {
  return (catalog?.steps || []).find((step) => step.type === stepType) || null;
}

export function findTriggerSpec(catalog, triggerKey) {
  return (catalog?.events || []).find((evt) => evt.key === triggerKey) || null;
}

export function extractStepOutcomes(stepObj, { rejectArrays = false } = {}) {
  if (!stepObj || typeof stepObj !== 'object' || (rejectArrays && Array.isArray(stepObj))) {
    return [];
  }

  if (stepObj.type === 'logic') {
    const cases = Array.isArray(stepObj.cases) ? stepObj.cases : [];
    const caseOutcomes = cases
      .map((item) => (item && typeof item === 'object' ? item.outcome : null))
      .filter((value) => typeof value === 'string');

    const defaultOutcome = typeof stepObj.default === 'string' ? [stepObj.default] : [];
    return uniqStrings([...caseOutcomes, ...defaultOutcome]);
  }

  if (stepObj.type === 'approval') {
    return uniqStrings([
      stepObj.approved_outcome,
      stepObj.rejected_outcome,
      stepObj.timeout_outcome,
    ]);
  }

  return [];
}
