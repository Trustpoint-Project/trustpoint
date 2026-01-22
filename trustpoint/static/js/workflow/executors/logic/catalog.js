// static/js/workflow/executors/logic/catalog.js
import { state } from '../../state.js';
import { fetchContextCatalog } from '../../ui-context.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }

function keyFromState() {
  const h = String(state.handler || '').trim();
  const p = String(state.protocol || '').trim();
  const o = String(state.operation || '').trim();
  return `h=${h}::p=${p}::o=${o}`;
}

function normalizePath(raw) {
  const s = String(raw || '').trim();
  if (!s) return '';
  return s.startsWith('ctx.') ? s : `ctx.${s}`;
}

function flattenCatalog(groups) {
  const out = [];
  for (const g of ensureArray(groups)) {
    const gname = String(g?.name || g?.label || g?.key || '').trim() || 'Variables';
    for (const v of ensureArray(g?.vars)) {
      const rawPath = v?.path ?? v?.key ?? '';
      const path = normalizePath(rawPath);
      if (!path) continue;
      out.push({
        group: gname,
        label: String(v?.label || path),
        path,
      });
    }
  }
  return out;
}

let _cacheKey = null;
let _cache = { groups: [] };
let _inflightKey = null;
let _inflightPromise = null;
let _reqId = 0;

/**
 * Return flattened catalog items: [{ group, label, path }]
 * Cached by handler/protocol/operation (from global wizard state).
 */
export async function getCatalogItems() {
  const h = String(state.handler || '').trim();
  if (!h) return [];

  const key = keyFromState();

  if (_cacheKey === key) return flattenCatalog(_cache.groups || []);
  if (_inflightKey === key && _inflightPromise) return _inflightPromise;

  const myReq = ++_reqId;

  _inflightKey = key;
  _inflightPromise = (async () => {
    const p = String(state.protocol || '').trim();
    const o = String(state.operation || '').trim();

    const cat = await fetchContextCatalog({ handler: h, protocol: p, operation: o })
      .catch(() => ({ groups: [] }));

    // Drop stale completions
    if (myReq !== _reqId) return flattenCatalog(_cache.groups || []);

    _cacheKey = key;
    _cache = (cat && Array.isArray(cat.groups)) ? cat : { groups: [] };
    return flattenCatalog(_cache.groups || []);
  })();

  try {
    return await _inflightPromise;
  } finally {
    if (_inflightKey === key) {
      _inflightKey = null;
      _inflightPromise = null;
    }
  }
}

/* Small aliases to avoid future import mismatches */
export const fetchCatalogItems = getCatalogItems;
export function peekCatalogItems() {
  if (_cacheKey !== keyFromState()) return [];
  return flattenCatalog(_cache.groups || []);
}
