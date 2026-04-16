import { escapeHtml } from '../shared/dom.js';

function normalizeIssue(raw, fallbackLevel = 'info') {
  if (!raw) {
    return null;
  }

  const level = String(raw.level || fallbackLevel).trim() || fallbackLevel;
  const message = String(raw.message || '').trim();
  if (!message) {
    return null;
  }

  const offset =
    typeof raw.offset === 'number' && Number.isFinite(raw.offset)
      ? raw.offset
      : null;

  const line =
    typeof raw.line === 'number' && Number.isFinite(raw.line)
      ? raw.line
      : null;

  const column =
    typeof raw.column === 'number' && Number.isFinite(raw.column)
      ? raw.column
      : null;

  return {
    level,
    message,
    offset,
    line,
    column,
  };
}

export function createIssuesPanelController({
  listEl,
  maxItems = 12,
  onSelectIssue = null,
}) {
  const groups = new Map();
  let renderedIssues = [];

  function flattenIssues() {
    const out = [];
    for (const groupIssues of groups.values()) {
      for (const issue of groupIssues) {
        out.push(issue);
      }
    }
    return out.slice(0, maxItems);
  }

  function render() {
    if (!listEl) {
      return;
    }

    renderedIssues = flattenIssues();

    if (!renderedIssues.length) {
      listEl.innerHTML = '<div class="text-muted">No current issues.</div>';
      return;
    }

    listEl.innerHTML = renderedIssues
      .map((item, index) => {
        const cls =
          item.level === 'error'
            ? 'wf2-issue-error'
            : item.level === 'warning'
              ? 'wf2-issue-warning'
              : 'wf2-issue-info';

        const locationText =
          item.line !== null
            ? `Line ${item.line}${item.column !== null ? `, column ${item.column}` : ''}`
            : '';

        const isClickable = item.offset !== null;
        const badgeClass =
          item.level === 'error'
            ? 'text-bg-danger'
            : item.level === 'warning'
              ? 'text-bg-warning'
              : 'text-bg-info';

        return `
          <button
            type="button"
            class="wf2-issue-item ${cls}${isClickable ? ' wf2-issue-clickable' : ''}"
            data-issue-index="${index}"
            ${isClickable ? 'title="Jump to this location"' : 'disabled'}
          >
            <div class="mb-2"><span class="badge ${badgeClass} text-capitalize">${escapeHtml(item.level)}</span></div>
            <div>${escapeHtml(item.message)}</div>
            ${
              locationText
                ? `<div class="small text-muted mt-1">${escapeHtml(locationText)}</div>`
                : ''
            }
          </button>
        `;
      })
      .join('');
  }

  function setGroup(groupKey, issueList) {
    const normalized = (issueList || [])
      .map((item) => normalizeIssue(item))
      .filter(Boolean);

    groups.set(groupKey, normalized);
    render();
  }

  function clearGroup(groupKey) {
    groups.delete(groupKey);
    render();
  }

  function add(level, message, meta = {}) {
    const nextIssue = normalizeIssue({
      level,
      message,
      ...meta,
    });

    if (!nextIssue) {
      return;
    }

    const manualKey = '__manual__';
    const prev = groups.get(manualKey) || [];
    const first = prev[0];

    if (
      first &&
      first.level === nextIssue.level &&
      first.message === nextIssue.message &&
      first.offset === nextIssue.offset
    ) {
      return;
    }

    groups.set(manualKey, [nextIssue, ...prev].slice(0, maxItems));
    render();
  }

  function clearAll() {
    groups.clear();
    render();
  }

  if (listEl) {
    listEl.addEventListener('click', (event) => {
      const button = event.target.closest('[data-issue-index]');
      if (!button) {
        return;
      }

      const index = Number(button.getAttribute('data-issue-index'));
      const issue = renderedIssues[index];
      if (!issue || issue.offset === null) {
        return;
      }

      onSelectIssue?.(issue);
    });
  }

  render();

  return {
    add,
    setGroup,
    clearGroup,
    clearAll,
    render,
  };
}
