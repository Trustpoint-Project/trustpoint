// static/js/workflow/executors/logic/styles.js
let _stylesInjected = false;

export function injectStylesOnce() {
  if (_stylesInjected) return;
  _stylesInjected = true;

  const style = document.createElement('style');
  style.textContent = `
    .lg-wrap { display:flex; flex-direction:column; gap:1rem; }
    .lg-topline { display:flex; align-items:center; justify-content:space-between; gap:.75rem; flex-wrap:wrap; }

    .lg-card {
      border:1px solid var(--bs-border-color,#dee2e6);
      border-radius:.75rem;
      padding:1rem;
      background: var(--bs-body-bg,#fff);
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
      background: rgba(13,110,253,.06);
      white-space:nowrap;
    }

    .lg-rule-tag.else {
      color: var(--bs-secondary-color,#6c757d);
      background: rgba(108,117,125,.08);
    }

    .lg-actions { display:flex; gap:.5rem; align-items:center; }

    .lg-row { display:flex; align-items:flex-end; gap:.5rem; flex-wrap:wrap; }

    .lg-conds { display:flex; flex-direction:column; gap:.75rem; }

    .lg-cond {
      border:1px solid var(--bs-border-color,#dee2e6);
      border-radius:.65rem;
      padding:.75rem;
      background: rgba(0,0,0,.01);
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
      background: rgba(108,117,125,.06);
    }

    .lg-divider { margin:1rem 0; opacity:.2; }
  `;
  document.head.appendChild(style);
}
