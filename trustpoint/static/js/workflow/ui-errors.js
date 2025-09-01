// static/js/ui-errors.js
// Render/clear a Bootstrap-styled error alert list.

function toArray(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  return [String(raw)];
}

export function clearErrors(containerEl) {
  if (!containerEl) return;
  containerEl.innerHTML = '';
  containerEl.classList.add('d-none');
  // Keep live region attributes so screen readers don't re-announce on clear
  containerEl.setAttribute('aria-live', 'polite');
  containerEl.setAttribute('aria-atomic', 'true');
}

export function renderErrors(containerEl, rawErrors) {
  if (!containerEl) return;
  const errors = toArray(rawErrors);
  containerEl.innerHTML = '';

  if (errors.length === 0) {
    containerEl.classList.add('d-none');
    return;
  }

  // Accessible live region
  containerEl.classList.remove('d-none');
  containerEl.setAttribute('aria-live', 'assertive');
  containerEl.setAttribute('aria-atomic', 'true');

  const alert = document.createElement('div');
  alert.className = 'alert alert-danger mb-2';
  alert.setAttribute('role', 'alert');

  const title = document.createElement('div');
  title.className = 'fw-semibold mb-1';
  title.textContent = 'Please fix the following:';
  alert.appendChild(title);

  const ul = document.createElement('ul');
  ul.className = 'mb-0';

  errors.forEach(msg => {
    const li = document.createElement('li');
    li.textContent = String(msg);
    ul.appendChild(li);
  });

  alert.appendChild(ul);
  containerEl.appendChild(alert);

  // Ensure it’s visible to the user
  try { containerEl.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch {}
}
