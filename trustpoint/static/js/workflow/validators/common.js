// static/js/workflow/validators/common.js
export function normalizeEmails(value) {
  if (!value) return [];
  const parts = Array.isArray(value) ? value.map(String) : String(value).split(',');
  return parts.map(s => s.trim()).filter(Boolean);
}

export function isPositiveInt(v) {
  if (v === null || v === undefined || v === '') return false;
  const n = Number(v);
  return Number.isInteger(n) && n > 0;
}

const SEGMENT_CHARS = new Set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'.split(''));
export function isDotPath(s) {
  if (typeof s !== 'string' || !s) return false;
  for (const ch of s) if (!SEGMENT_CHARS.has(ch)) return false;
  const parts = s.split('.');
  return parts.every(p => p && (/[A-Za-z_]/.test(p[0])) && (/^[A-Za-z0-9_]+$/.test(p)));
}
