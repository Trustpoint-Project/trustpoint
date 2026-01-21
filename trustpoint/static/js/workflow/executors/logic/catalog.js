// static/js/workflow/executors/logic/catalog.js
import { state } from '../../state.js';
import { fetchContextCatalog } from '../../ui-context.js';

function ensureArray(v) { return Array.isArray(v) ? v : []; }

let _catalogCacheKey = null;
let _catalogCache = { groups: [] };
let _catalogReq = 0;
let _inflightKey = null;
let _inflightPromise = null;

function catalogKeyFromState() {
  const h = String(state.handler || '').trim();
  const p = String(state.protocol || '').trim();
  const o = String(state.operation || '').trim();
  return `h=${h}::p=${p}::o=${o}`;
}

function flattenCatalog(groups) {
  const out = [];
  for (const g of ensureArray(groups)) {
    const gname = String(g?.name || g?.label || '').trim() || 'Variables';
    for (const v of ensureArray(g?.vars)) {
      const path = String(v?.path || v?.key || '').trim();
      if (!path) continue;
      out.push({ group: gname, label: String(v?.label || path), path });
    }
  }
  return out;
}

export async function getCatalogItems() {
  const h = String(state.handler || '').trim();
  const p = String(state.protocol || '').trim();
  const o = String(state.operation || '').trim();
  if (!h) return [];

  const key = catalogKeyFromState();

  if (_catalogCacheKey === key) return flattenCatalog(_catalogCache.groups || []);
  if (_inflightKey === key && _inflightPromise) return _inflightPromise;

  const reqId = ++_catalogReq;

  _inflightKey = key;
  _inflightPromise = (async () => {
    const cat = await fetchContextCatalog({ handler: h, protocol: p, operation: o }).catch(() => ({ groups: [] }));
    if (reqId !== _catalogReq) return flattenCatalog(_catalogCache.groups || []);
    _catalogCacheKey = key;
    _catalogCache = (cat && Array.isArray(cat.groups)) ? cat : { groups: [] };
    return flattenCatalog(_catalogCache.groups || []);
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
