function readValue(scope, selector) {
  return scope?.querySelector(selector)?.value ?? '';
}

export function readWebhookCaptureRows(scope) {
  return [...(scope?.querySelectorAll('[data-capture-row]') || [])].map((row) => ({
    target: readValue(row, '[data-capture-target-input="true"]'),
    source: readValue(row, '[data-capture-source-input="true"]'),
  }));
}

export function readComputeAssignmentRows(scope) {
  return [...(scope?.querySelectorAll('[data-compute-row]') || [])].map((row) => ({
    target: readValue(row, '[data-compute-target-input="true"]'),
    operator: readValue(row, '[data-compute-operator-input="true"]'),
    argsText: readValue(row, '[data-compute-args-input="true"]'),
  }));
}

export function readSetVarRows(scope) {
  return [...(scope?.querySelectorAll('[data-set-var-row]') || [])].map((row) => ({
    key: readValue(row, '[data-set-var-key-input="true"]'),
    value: readValue(row, '[data-set-var-value-input="true"]'),
  }));
}
