export function $(selector, root = document) {
  return root.querySelector(selector);
}

export function text(el, value) {
  if (el) {
    el.textContent = value;
  }
}

export function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

export function renderChips(items, renderItem) {
  if (!Array.isArray(items) || !items.length) {
    return '<span class="text-muted">None</span>';
  }
  return items.map(renderItem).join('');
}