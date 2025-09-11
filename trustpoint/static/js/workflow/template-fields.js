// Track templatable inputs and provide caret insertion.
// Now remembers the *last* focused templatable field so Insert works
// even if the side panel steals focus.

let activeEl = null;           // currently focused templatable
let lastTemplatableEl = null;  // last known templatable (sticky across blur)
const tracked = new WeakSet();

/** Mark one input/textarea as templatable and hook focus tracking. */
export function markTemplatable(el) {
  if (!el || tracked.has(el)) return;
  tracked.add(el);
  el.dataset.template = 'django';

  const tag = (el.tagName || '').toUpperCase();
  const isText = tag === 'TEXTAREA' ||
    (tag === 'INPUT' && /^(text|email|search|url|tel)$/i.test(el.type || 'text'));
  if (!isText) return;

  el.addEventListener('focus', () => {
    activeEl = el;
    lastTemplatableEl = el;
  }, { passive: true });

  el.addEventListener('blur', () => {
    // keep lastTemplatableEl sticky; only clear activeEl
    if (activeEl === el) activeEl = null;
  }, { passive: true });

  if (document.activeElement === el) {
    activeEl = el;
    lastTemplatableEl = el;
  }
}

/** Scan a container for likely templatable fields. */
export function registerTemplatableFields(root) {
  if (!root) return;
  const nodes = root.querySelectorAll(
    'textarea, input[type="text"], input[type="email"], input[type="search"], input[data-template]'
  );
  nodes.forEach(n => markTemplatable(n));
}

/** Prefer the active templatable; fall back to the last one. */
export function getActiveTemplatable() {
  if (activeEl && tracked.has(activeEl)) return activeEl;
  if (lastTemplatableEl && tracked.has(lastTemplatableEl)) return lastTemplatableEl;
  return null;
}

/** Insert text at caret of the active/last templatable; returns boolean. */
export function insertIntoActive(text) {
  const el = getActiveTemplatable();
  if (!el) return false;

  const start = el.selectionStart ?? el.value.length;
  const end   = el.selectionEnd ?? el.value.length;
  const before = el.value.slice(0, start);
  const after  = el.value.slice(end);
  el.value = before + text + after;

  const pos = before.length + text.length;
  try { el.setSelectionRange(pos, pos); } catch {}
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.focus(); // return focus to the field
  return true;
}
