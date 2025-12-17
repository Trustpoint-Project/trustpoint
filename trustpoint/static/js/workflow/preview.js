import { buildPayload } from './state.js';

export function renderPreview(preEl) {
  const payload = buildPayload();
  preEl.textContent = JSON.stringify(payload, null, 2);
}
