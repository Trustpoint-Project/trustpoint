import { getTrigger, getTriggerSources, parseRoot, stringifyRoot } from '../yaml_document.js';

const SOURCE_LIST_KEYS = new Set(['ca_ids', 'domain_ids', 'device_ids']);

function ensureSourceShape(sources) {
  if (typeof sources.trustpoint !== 'boolean') {
    sources.trustpoint = Boolean(sources.trustpoint);
  }

  for (const key of SOURCE_LIST_KEYS) {
    if (!Array.isArray(sources[key])) {
      sources[key] = [];
    }
  }
}

function normalizeSourceListKey(sourceKind) {
  if (!SOURCE_LIST_KEYS.has(sourceKind)) {
    throw new Error(`Unsupported trigger source list "${sourceKind}".`);
  }

  return sourceKind;
}

function normalizeSourceValue(sourceKind, rawValue) {
  if (rawValue == null) {
    throw new Error('No source value selected.');
  }

  const trimmed = String(rawValue).trim();
  if (!trimmed) {
    throw new Error('Source value cannot be empty.');
  }

  if (sourceKind === 'device_ids') {
    return trimmed;
  }

  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isInteger(parsed)) {
    throw new Error(`"${trimmed}" is not a valid ${sourceKind} value.`);
  }

  return parsed;
}

function hasSourceValue(list, value) {
  return list.some((item) => String(item) === String(value));
}

export function setTriggerTrustpoint({ yamlText, enabled }) {
  const rootObj = parseRoot(yamlText);
  const sources = getTriggerSources(rootObj);
  ensureSourceShape(sources);

  const nextValue = Boolean(enabled);
  const changed = sources.trustpoint !== nextValue;
  sources.trustpoint = nextValue;

  return {
    changed,
    yamlText: changed ? stringifyRoot(rootObj) : yamlText,
  };
}

export function setTriggerOn({ yamlText, triggerKey }) {
  const rootObj = parseRoot(yamlText);
  const trigger = getTrigger(rootObj);
  const nextValue = String(triggerKey || '').trim();

  if (!nextValue) {
    throw new Error('No trigger selected.');
  }

  const changed = String(trigger.on || '') !== nextValue;
  trigger.on = nextValue;

  return {
    changed,
    yamlText: changed ? stringifyRoot(rootObj) : yamlText,
  };
}

export function addTriggerSourceValue({ yamlText, sourceKind, rawValue }) {
  const rootObj = parseRoot(yamlText);
  const sources = getTriggerSources(rootObj);
  const listKey = normalizeSourceListKey(sourceKind);
  const value = normalizeSourceValue(listKey, rawValue);

  ensureSourceShape(sources);

  if (hasSourceValue(sources[listKey], value)) {
    return {
      changed: false,
      yamlText,
    };
  }

  sources[listKey].push(value);

  return {
    changed: true,
    yamlText: stringifyRoot(rootObj),
  };
}

export function removeTriggerSourceValue({ yamlText, sourceKind, rawValue }) {
  const rootObj = parseRoot(yamlText);
  const sources = getTriggerSources(rootObj);
  const listKey = normalizeSourceListKey(sourceKind);
  const value = normalizeSourceValue(listKey, rawValue);

  ensureSourceShape(sources);

  const nextValues = sources[listKey].filter((item) => String(item) !== String(value));
  if (nextValues.length === sources[listKey].length) {
    return {
      changed: false,
      yamlText,
    };
  }

  sources[listKey] = nextValues;

  return {
    changed: true,
    yamlText: stringifyRoot(rootObj),
  };
}
