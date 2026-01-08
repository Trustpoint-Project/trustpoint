// trustpoint/static/js/workflows/unified-requests.js
//
// UX rule:
// - If state is Finalized or Aborted -> include_finalized MUST be checked
// - Otherwise -> include_finalized MUST be unchecked
//
// No inline JS required; this module runs on DOMContentLoaded.

function normalize(v) {
  return String(v || '').trim().toLowerCase();
}

function syncIncludeFinalized({ stateEl, includeEl }) {
  const s = normalize(stateEl.value);

  // Matches State enum raw values ("Finalized", "Aborted")
  const mustInclude = (s === 'finalized' || s === 'aborted');
  includeEl.checked = mustInclude;
}

function init() {
  const form = document.getElementById('unified-filter-form');
  if (!form) return;

  const stateEl = form.querySelector('[name="state"]');
  const includeEl = form.querySelector('[name="include_finalized"]');
  if (!stateEl || !includeEl) return;

  // Initial sync (covers page load with query params)
  syncIncludeFinalized({ stateEl, includeEl });

  // Sync on user change
  stateEl.addEventListener('change', () => syncIncludeFinalized({ stateEl, includeEl }));
}

document.addEventListener('DOMContentLoaded', init);
