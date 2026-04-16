import { parseDocument } from 'yaml';

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

export function normalizeVarsTarget(rawValue, fallback = 'vars.value') {
  const trimmed = String(rawValue || '').trim();
  if (!trimmed) {
    return fallback;
  }

  return trimmed.startsWith('vars.') ? trimmed : `vars.${trimmed}`;
}

export function parseScalarValue(rawValue) {
  const text = String(rawValue ?? '').trim();

  if (!text) {
    return '';
  }

  if (text === 'true') {
    return true;
  }
  if (text === 'false') {
    return false;
  }
  if (text === 'null') {
    return null;
  }

  if (/^-?\d+$/.test(text)) {
    return Number.parseInt(text, 10);
  }

  if (/^-?\d+\.\d+$/.test(text)) {
    return Number.parseFloat(text);
  }

  return text;
}

export function parseYamlValue(rawValue, label) {
  const text = String(rawValue ?? '');

  if (!text.trim()) {
    return '';
  }

  const doc = parseDocument(text, { prettyErrors: true });
  if (doc.errors.length) {
    throw new Error(`${label}: ${String(doc.errors[0])}`);
  }

  return doc.toJS();
}

export function parseStructuredYaml(rawValue, label) {
  const text = String(rawValue || '').trim();
  if (!text) {
    return null;
  }

  return parseYamlValue(text, label);
}

export function parseMultilineArgs(rawValue) {
  return String(rawValue || '')
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map(parseScalarValue);
}
