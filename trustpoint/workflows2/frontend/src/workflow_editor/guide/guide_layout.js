import { escapeHtml } from '../shared/dom.js';

function renderFallback(message) {
  return `<div class="text-muted">${escapeHtml(message)}</div>`;
}

export function renderGuidePage({
  title,
  description = '',
  current = '',
  actions = '',
  reference = '',
}) {
  return `
    <div class="wf2-guide-page">
      <div class="wf2-guide-page-header">
        <div class="wf2-guide-page-title">${escapeHtml(title || 'Workflow document')}</div>
        <div class="wf2-guide-page-summary">${escapeHtml(description || '')}</div>
      </div>

      <div class="wf2-guide-page-sections">
        ${renderGuideSection({
          title: 'Current',
          description: 'Only the information tied to the current cursor position.',
          tone: 'accent',
          body: current || renderFallback('Nothing selected yet.'),
        })}
        ${renderGuideSection({
          title: 'Actions',
          description: 'Small targeted helpers for the current section.',
          body: actions || renderFallback('No quick action for this section.'),
        })}
        ${renderGuideSection({
          title: 'Reference',
          description: 'Minimal supporting reference while YAML stays authoritative.',
          body: reference || renderFallback('No extra reference for this section.'),
        })}
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
