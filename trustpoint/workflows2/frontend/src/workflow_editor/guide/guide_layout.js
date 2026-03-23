import { escapeHtml } from '../shared/dom.js';

export function renderGuidePage({
  title,
  description = '',
  pathLabel = '(root)',
  body = '',
}) {
  return `
    <div class="wf2-guide-page">
      <div class="wf2-guide-page-header">
        <div class="wf2-guide-page-kicker">Context-aware editor guide</div>
        <div class="wf2-guide-page-title">${escapeHtml(title || 'Workflow document')}</div>
        <div class="wf2-guide-page-summary">${escapeHtml(description || '')}</div>
        <div class="wf2-guide-path-pill">
          <span>Path</span>
          <code>${escapeHtml(pathLabel || '(root)')}</code>
        </div>
      </div>

      <div class="wf2-guide-page-sections">
        ${body}
      </div>
    </div>
  `;
}

export function renderGuideSection({
  title,
  description = '',
  body = '',
  tone = 'default',
  className = '',
}) {
  return `
    <section class="wf2-guide-section wf2-guide-section-${escapeHtml(tone)}${className ? ` ${escapeHtml(className)}` : ''}">
      <div class="wf2-guide-section-head">
        <div class="wf2-guide-section-title">${escapeHtml(title || '')}</div>
        ${description ? `<div class="wf2-guide-section-description">${escapeHtml(description)}</div>` : ''}
      </div>
      <div class="wf2-guide-section-body">
        ${body}
      </div>
    </section>
  `;
}

export function renderGuideButtonRow(content) {
  return `<div class="wf2-guide-button-row">${content || '<span class="text-muted">None</span>'}</div>`;
}

export function renderGuideMeta(items) {
  const entries = (items || [])
    .filter((item) => item && item.value != null && String(item.value).trim())
    .map((item) => `
      <div class="wf2-guide-meta-pill">
        <span class="wf2-guide-meta-label">${escapeHtml(item.label || '')}</span>
        <strong>${escapeHtml(item.value)}</strong>
      </div>
    `)
    .join('');

  if (!entries) {
    return '';
  }

  return `<div class="wf2-guide-meta-row">${entries}</div>`;
}

export function renderGuideNote(message, tone = 'muted') {
  return `<div class="wf2-guide-note wf2-guide-note-${escapeHtml(tone)}">${escapeHtml(message)}</div>`;
}
