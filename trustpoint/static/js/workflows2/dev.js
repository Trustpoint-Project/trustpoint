document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('ir_data');
  if (!el) {
    return;
  }

  const pre = el.closest('pre');
  if (!pre) {
    return;
  }

  try {
    const obj = JSON.parse(el.textContent || '{}');
    pre.textContent = JSON.stringify(obj, null, 2);
  } catch {
    // Leave the original payload in place if parsing fails.
  }
});
