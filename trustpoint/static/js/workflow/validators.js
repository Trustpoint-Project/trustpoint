// static/js/validators.js
// Client-side validator mirroring the server rules (now with BARE variable paths).

function normalizeEmails(value) {
  if (!value) return [];
  const parts = Array.isArray(value)
    ? value.map(String)
    : String(value).split(',');
  return parts.map(s => s.trim()).filter(Boolean);
}

const SEGMENT_CHARS = new Set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'.split(''));

function isDotPath(s) {
  if (typeof s !== 'string' || !s) return false;
  for (const ch of s) if (!SEGMENT_CHARS.has(ch)) return false;
  const parts = s.split('.');
  // Strip underscores for the alnum check (fix: previously a no-op)
  return parts.every(p =>
    p &&
    (/[A-Za-z_]/.test(p[0])) &&
    (/^[A-Za-z0-9]+$/.test(p.replaceAll('_','')))
  );
}

function knownTriples(triggersMap) {
  // Build set of (handler, protocol, operation) from the API map.
  const set = new Set();
  Object.values(triggersMap || {}).forEach(t => {
    const h = (t.handler || '').trim();
    const p = (t.protocol || '').trim();
    const o = (t.operation || '').trim();
    set.add([h, p, o].join('||'));
    // allow empty p/o for non-certificate handlers (defensive)
    if (!p && !o) set.add([h, '', ''].join('||'));
  });
  return set;
}

export function validateWizardState(state, triggersMap) {
  const errors = [];

  // name
  if (!state.name || !state.name.trim()) {
    errors.push('Name is required.');
  }

  // trigger (we only support single trigger in UI)
  const h = (state.handler || '').trim();
  const p = (state.protocol || '').trim();
  const o = (state.operation || '').trim();
  if (!h) {
    errors.push('Event type (handler) is required.');
  } else {
    const triples = knownTriples(triggersMap);
    if (h === 'certificate_request') {
      if (!p || !o) {
        errors.push('Protocol and operation are required for certificate_request.');
      } else if (!triples.has([h, p, o].join('||'))) {
        errors.push('Unknown handler/protocol/operation combination.');
      }
    } else {
      // non-certificate: allow empty p/o
      const key = [h, p || '', o || ''].join('||');
      if (!triples.has(key)) {
        errors.push('Unknown event type selection.');
      }
    }
  }

  // steps
  const allowed = new Set(['Approval', 'Email', 'Webhook', 'Timer', 'Condition']);
  if (!Array.isArray(state.steps) || state.steps.length === 0) {
    errors.push('At least one step is required.');
  } else {
    state.steps.forEach((s, idx) => {
      const i = idx + 1;
      if (!allowed.has(s.type)) {
        errors.push(`Step #${i}: unknown type "${s.type}".`);
        return;
      }
      const params = s.params || {};
      if (s.type === 'Email') {
        const to = normalizeEmails(params.recipients || '');
        if (to.length === 0) {
          errors.push(`Step #${i} (Email): at least one recipient is required.`);
        }
        const hasTpl = !!(params.template || '').trim();
        if (!hasTpl) {
          if (!params.subject || !String(params.subject).trim()) {
            errors.push(`Step #${i} (Email): subject is required in custom mode.`);
          }
          if (!params.body || !String(params.body).trim()) {
            errors.push(`Step #${i} (Email): body is required in custom mode.`);
          }
        }
      }
      if (s.type === 'Webhook') {
        const url = (params.url || '').trim();
        if (!/^https?:\/\//i.test(url)) {
          errors.push(`Step #${i} (Webhook): url is required and must start with http:// or https://.`);
        }
        const method = (params.method || 'POST').toUpperCase();
        if (!['GET','POST','PUT','PATCH','DELETE'].includes(method)) {
          errors.push(`Step #${i} (Webhook): method must be one of GET, POST, PUT, PATCH, DELETE.`);
        }
        const resultTo = (params.result_to || '').trim();
        if (resultTo && !isDotPath(resultTo)) {
          errors.push(`Step #${i} (Webhook): result_to must be a variable path like "serial_number" or "http.status".`);
        }
        const resultSource = (params.result_source || 'auto').trim().toLowerCase();
        if (resultSource && !['auto','json','text','status','headers'].includes(resultSource)) {
          errors.push(`Step #${i} (Webhook): result_source must be one of auto/json/text/status/headers.`);
        }
        const exportsArr = params.exports || [];
        if (exportsArr != null && !Array.isArray(exportsArr)) {
          errors.push(`Step #${i} (Webhook): exports must be an array if provided.`);
        } else if (Array.isArray(exportsArr)) {
          const seen = new Set();
          exportsArr.forEach((e, j) => {
            const fromPath = String((e && e.from_path) || '').trim();
            const toPath = String((e && e.to_path) || '').trim();
            if (!fromPath) {
              errors.push(`Step #${i} (Webhook): export #${j+1} from_path is required.`);
            } else if (!(fromPath === 'status' || fromPath === 'text' || fromPath === 'json' || fromPath === 'headers' ||
                       fromPath.startsWith('json.') || fromPath.startsWith('headers.'))) {
              errors.push(`Step #${i} (Webhook): export #${j+1} from_path must be "status", "text", "json[.path]" or "headers[.path]".`);
            } else if ((fromPath.startsWith('json.') || fromPath.startsWith('headers.')) && !isDotPath(fromPath)) {
              errors.push(`Step #${i} (Webhook): export #${j+1} from_path has an invalid path segment.`);
            }
            if (!toPath || !isDotPath(toPath)) {
              errors.push(`Step #${i} (Webhook): export #${j+1} to_path must be a variable path like "serial_number" or "http.status".`);
            } else if (seen.has(toPath)) {
              errors.push(`Step #${i} (Webhook): duplicate to_path "${toPath}" in exports.`);
            } else {
              seen.add(toPath);
            }
          });
        }
      }
    });
  }

  // scopes (support Set or Array gracefully)
  const caCount = Array.isArray(state.scopes?.CA) ? state.scopes.CA.length : (state.scopes?.CA?.size || 0);
  const domCount = Array.isArray(state.scopes?.Domain) ? state.scopes.Domain.length : (state.scopes?.Domain?.size || 0);
  const devCount = Array.isArray(state.scopes?.Device) ? state.scopes.Device.length : (state.scopes?.Device?.size || 0);
  const scopeCount = (caCount || 0) + (domCount || 0) + (devCount || 0);
  if (scopeCount === 0) {
    errors.push('At least one scope (CA/Domain/Device) is required.');
  }

  return errors;
}
