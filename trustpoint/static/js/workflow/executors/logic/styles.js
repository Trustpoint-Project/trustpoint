// static/js/workflow/executors/logic/styles.js
let _stylesInjected = false;

export function injectStylesOnce() {
  if (_stylesInjected) return;
  _stylesInjected = true;

  const style = document.createElement('style');
  style.textContent = `
    /* Prevent browser scroll anchoring from "jumping" when Logic async renders */
    .ww-step-card.logic-step,
    .ww-step-card.logic-step * ,
    .lg-wrap,
    .lg-wrap * ,
    .lg-card,
    .lg-card * {
      overflow-anchor: none;
    }

    .lg-wrap { display:flex; flex-direction:column; gap:1rem; }
    .lg-topline { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; }

    .lg-card {
      border:1px solid var(--bs-border-color,#dee2e6);
      border-radius:.75rem;
      padding:1rem;
      background: var(--bs-body-bg,#fff);
      color: var(--bs-body-color, #212529);
    }

    .lg-subtle {
      font-size:.9rem;
      color: var(--bs-secondary-color,#6c757d);
      margin:.25rem 0 0;
    }

    .lg-section-title { font-weight:700; font-size:.95rem; margin:.25rem 0 .75rem; }

    .lg-rule-head {
      display:flex; align-items:center; justify-content:space-between;
      gap:.75rem; flex-wrap:wrap; margin-bottom:.75rem;
    }

    .lg-rule-tag {
      display:inline-flex; align-items:center;
      font-weight:700; font-size:.8rem; letter-spacing:.02em;
      text-transform:uppercase;
      padding:.15rem .5rem;
      border-radius:999px;
      border:1px solid var(--bs-border-color,#dee2e6);
      color: var(--bs-primary,#0d6efd);
      background: color-mix(in srgb, var(--bs-primary,#0d6efd) 10%, transparent);
      white-space:nowrap;
    }

    .lg-rule-tag.else {
      color: var(--bs-secondary-color,#6c757d);
      background: color-mix(in srgb, var(--bs-secondary-color,#6c757d) 14%, transparent);
    }

    .lg-actions { display:flex; gap:.5rem; align-items:center; }

    .lg-row { display:flex; align-items:flex-end; gap:.5rem; flex-wrap:wrap; }

    /* ---------- Conditions grouping ---------- */
    .lg-conds-top {
      display:flex;
      align-items:flex-end;
      justify-content:space-between;
      gap: .75rem;
      flex-wrap:wrap;
      margin-top: .25rem;
    }
    .lg-conds-mode .mb-2 { margin-bottom: 0 !important; }

    .lg-conds-group {
      margin-top: .35rem;
      padding: .85rem;
      border-radius: .75rem;
      border: 1px solid var(--bs-border-color,#dee2e6);
      background: var(--bs-tertiary-bg, rgba(0,0,0,.02));
      border-left: 4px solid color-mix(in srgb, var(--bs-secondary-color,#6c757d) 45%, transparent);
    }

    .lg-conds { display:flex; flex-direction:column; gap:.75rem; margin-top: .35rem; }

    .lg-cond {
      border:1px solid var(--bs-border-color,#dee2e6);
      border-radius:.65rem;
      padding:.75rem;
      background: var(--bs-body-bg,#fff);
      color: var(--bs-body-color, #212529);
    }

    .lg-cond-grid {
      display:grid;
      grid-template-columns: 1fr 180px 1fr;
      gap:.75rem;
      align-items:end;
    }

    @media (max-width: 1000px) {
      .lg-cond-grid { grid-template-columns: 1fr; }
    }

    .lg-cond-actions {
      display:flex;
      justify-content:space-between;
      align-items:center;
      margin-top:.5rem;
      gap:.75rem;
      flex-wrap:wrap;
    }

    .lg-join-pill {
      display:inline-flex;
      align-items:center;
      justify-content:center;
      font-weight:700;
      font-size:.75rem;
      letter-spacing:.02em;
      text-transform:uppercase;
      padding:.15rem .55rem;
      border-radius:999px;
      border:1px solid var(--bs-border-color,#dee2e6);
      color: var(--bs-secondary-color,#6c757d);
      background: var(--bs-body-bg,#fff);
      align-self: center;
    }

    .lg-conds-footer {
      display:flex;
      justify-content:flex-start;
      padding-top: .25rem;
    }

    .lg-divider { margin:1rem 0; opacity:.2; }

    /* ---------- Branch box to show conditional execution ---------- */
    .lg-branch {
      margin-top: .5rem;
      padding: .85rem .85rem .75rem;
      border-radius: .75rem;
      border: 1px solid var(--bs-border-color,#dee2e6);
      background: color-mix(in srgb, var(--bs-primary,#0d6efd) 6%, var(--bs-body-bg,#fff));
      border-left: 4px solid color-mix(in srgb, var(--bs-primary,#0d6efd) 45%, transparent);
    }
    .lg-branch.lg-branch-else {
      background: color-mix(in srgb, var(--bs-secondary-color,#6c757d) 6%, var(--bs-body-bg,#fff));
      border-left-color: color-mix(in srgb, var(--bs-secondary-color,#6c757d) 45%, transparent);
    }
    .lg-branch-head {
      display:flex;
      align-items:center;
      justify-content:space-between;
      gap: .75rem;
      flex-wrap:wrap;
      margin-bottom: .6rem;
    }
    .lg-branch-tag {
      display:inline-flex;
      align-items:center;
      font-weight:800;
      font-size:.75rem;
      letter-spacing:.03em;
      text-transform:uppercase;
      padding:.18rem .55rem;
      border-radius:999px;
      border:1px solid var(--bs-border-color,#dee2e6);
      background: var(--bs-body-bg,#fff);
      color: var(--bs-secondary-color,#6c757d);
      white-space:nowrap;
    }
    .lg-branch-hint {
      font-size:.85rem;
      color: var(--bs-secondary-color,#6c757d);
    }

    /* ---------- Expression operand wrapper (new kind) ---------- */
    .lg-operand-expr > .mb-2 { margin-bottom: .35rem !important; }
    .lg-operand-expr {
      padding: .6rem;
      border-radius: .65rem;
      border: 1px dashed var(--bs-border-color,#dee2e6);
      background: var(--bs-tertiary-bg, rgba(0,0,0,.02));
    }
  `;
  document.head.appendChild(style);
}
