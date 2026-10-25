export function debounce(fn, wait) {
  let timer = null;

  return (...args) => {
    clearTimeout(timer);
    timer = window.setTimeout(() => fn(...args), wait);
  };
}

export function deepClone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

export function uniqStrings(values) {
  const out = [];
  const seen = new Set();

  for (const value of values || []) {
    if (typeof value !== 'string') {
      continue;
    }

    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }

    seen.add(normalized);
    out.push(normalized);
  }

  return out;
}
