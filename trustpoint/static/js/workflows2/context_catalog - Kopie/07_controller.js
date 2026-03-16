// static/js/workflows2/context_catalog/07_controller.js
(function () {
  const WF2CC = window.WF2CC;

  const state = {
    drawer: null,
    searchEl: null,
    groupsEl: null,
    listEl: null,
    pillEl: null,

    catalog: { events: [], steps: [], presets: [] },

    tab: "insert",
    mode: "allowed",
    selectedGroup: null,

    autoTab: true,
    manualTab: false,

    lastActiveField: null,

    getInsertTarget() {
      return this.lastActiveField || WF2CC.getYamlTextarea();
    },
  };

  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT")) {
      state.lastActiveField = el;
    }
  });

  function createFabIfMissing() {
    if (document.getElementById("wf2-open-vars")) return;
    if (document.getElementById("wf2cc-fab")) return;

    const fab = document.createElement("div");
    fab.id = "wf2cc-fab";
    fab.style.cssText = `
      position: fixed; right: 16px; bottom: 16px; z-index: 2099;
      display: inline-flex; align-items:center; gap:.35rem;
      border-radius: 999px; padding: .45rem .75rem;
      border: 1px solid rgba(255,255,255,.2);
      background: rgba(0,0,0,.65); color: #fff; cursor: pointer;
      user-select: none; font-size: .9rem;
    `;
    fab.innerHTML = `Catalog <span style="opacity:.85;font-size:.8rem;">Ctrl/⌘+K</span>`;
    fab.addEventListener("click", () => WF2CC.toggle(state));
    document.body.appendChild(fab);
  }

  async function init() {
    WF2CC.ensureDrawer(state);
    createFabIfMissing();

    const yamlEl = WF2CC.getYamlTextarea();
    if (yamlEl) WF2CC.enableTextareaIndent(yamlEl);

    const btn = document.getElementById("wf2-open-vars");
    if (btn) btn.addEventListener("click", () => WF2CC.toggle(state));

    window.addEventListener("keydown", (e) => {
      const k = String(e.key || "").toLowerCase();

      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && k === "k") {
        e.preventDefault();
        WF2CC.toggle(state);
        return;
      }
      if (state.drawer && state.drawer.classList.contains("open") && e.key === "Escape") {
        e.preventDefault();
        WF2CC.close(state);
        return;
      }

      // undo/redo while drawer open:
      if (state.drawer && state.drawer.classList.contains("open")) {
        const isUndo = (e.ctrlKey || e.metaKey) && !e.shiftKey && k === "z";
        const isRedo = (e.ctrlKey && k === "y") || ((e.metaKey || e.ctrlKey) && e.shiftKey && k === "z");
        if (isUndo || isRedo) {
          const target = state.getInsertTarget() || WF2CC.getYamlTextarea();
          if (target && (target.tagName === "TEXTAREA" || target.tagName === "INPUT")) {
            e.preventDefault();
            target.focus();
            document.execCommand(isUndo ? "undo" : "redo");
          }
        }
      }
    });

    if (yamlEl) {
      const rer = WF2CC.debounce(() => {
        if (state.drawer.classList.contains("open")) WF2CC.render(state);
      }, 120);
      yamlEl.addEventListener("input", rer);
      yamlEl.addEventListener("click", rer);
      yamlEl.addEventListener("keyup", rer);
    }

    try {
      state.catalog = await WF2CC.loadCatalog();
      WF2CC.render(state);
    } catch (err) {
      state.catalog = { events: [], steps: [], presets: [] };
      state.groupsEl.innerHTML = `<div class="wf2cc-error">${WF2CC.esc(err && err.stack ? err.stack : String(err))}</div>`;
      state.listEl.innerHTML = `<div class="wf2cc-empty">Failed to load context catalog.</div>`;
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
