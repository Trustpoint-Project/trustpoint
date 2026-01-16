// static/js/workflow/validators/webhook.js
import { isDotPath } from './common.js';

export function validateWebhook(step, i, errors) {
  const p = step.params || {};
  const url = (p.url || '').trim();
  if (!/^https?:\/\//i.test(url)) {
    errors.push(`Step #${i} (Webhook): url is required and must start with http:// or https://.`);
  }
  const method = (p.method || 'POST').toUpperCase();
  if (!['GET','POST','PUT','PATCH','DELETE'].includes(method)) {
    errors.push(`Step #${i} (Webhook): method must be one of GET, POST, PUT, PATCH, DELETE.`);
  }
  const resultTo = (p.webhook_variable || '').trim();
  if (resultTo && !isDotPath(resultTo)) {
    errors.push(`Step #${i} (Webhook): webhook_variable must be a variable path like "serial_number" or "http.status".`);
  }
  const resultSource = (p.result_source || 'auto').trim().toLowerCase();
  if (resultSource && !['auto','json','text','status','headers'].includes(resultSource)) {
    errors.push(`Step #${i} (Webhook): result_source must be one of auto/json/text/status/headers.`);
  }

  const exportsArr = p.exports || [];
  if (exportsArr != null && !Array.isArray(exportsArr)) {
    errors.push(`Step #${i} (Webhook): exports must be an array if provided.`);
  } else if (Array.isArray(exportsArr)) {
    const seen = new Set();
    exportsArr.forEach((e, j) => {
      const fromPath = String((e && e.from_path) || '').trim();
      const toPath   = String((e && e.to_path) || '').trim();
      if (!fromPath) {
        errors.push(`Step #${i} (Webhook): export #${j+1} from_path is required.`);
      } else if (!(fromPath === 'status' || fromPath === 'text' || fromPath === 'json' || fromPath === 'headers' ||
                 fromPath.startsWith('json.') || fromPath.startsWith('headers.'))) {
        errors.push(`Step #${i} (Webhook): export #${j+1} from_path must be "status", "text", "json[.path]" or "headers[.path]".`);
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
