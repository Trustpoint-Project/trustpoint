// static/js/workflows2/context_catalog/52_ui_toolbar.js
(function () {
  const WF2CC = window.WF2CC;

  WF2CC.ui.ensureToolbar = function ensureToolbar(state) {
    if (document.getElementById("wf2cc-toolbar")) return;

    const style = document.createElement("style");
    style.textContent = `
      .wf2cc-toolbar{
        position: fixed; right: 16px; bottom: 64px; z-index: 2098;
        display:flex; align-items:center; gap:.5rem;
        padding:.45rem .55rem; border-radius: 999px;
        border: 1px solid var(--bs-border-color, rgba(0,0,0,.15));
        background: var(--bs-body-bg, #fff);
        color: var(--bs-body-color, #111);
        box-shadow: 0 6px 18px rgba(0,0,0,.14);
      }
      .wf2cc-seg{
        display:flex; align-items:center;
        border: 1px solid var(--bs-border-color, rgba(0,0,0,.15));
        border-radius: 999px;
        overflow:hidden;
      }
      .wf2cc-seg button{
        border:0; background:transparent; color:inherit;
        padding:.25rem .6rem; font-size:.85rem; cursor:pointer;
      }
      .wf2cc-seg button.sel{
        background: rgba(13,110,253,.18);
        color: var(--bs-body-color, #111);
        font-weight: 600;
      }
      .wf2cc-toolbtn{
        border: 1px solid var(--bs-border-color, rgba(0,0,0,.15));
        background: transparent;
        color: inherit;
        padding:.25rem .6rem;
        border-radius: 999px;
        font-size:.85rem;
        cursor:pointer;
      }
      .wf2cc-toolbtn:hover{
        background: rgba(0,0,0,.05);
      }

      /* Dark mode: keep same readability */
      @media (prefers-color-scheme: dark) {
        .wf2cc-toolbar{
          background: rgba(0,0,0,.72);
          color: #fff;
          border-color: rgba(255,255,255,.18);
        }
        .wf2cc-seg{ border-color: rgba(255,255,255,.18); }
        .wf2cc-toolbtn{ border-color: rgba(255,255,255,.18); }
        .wf2cc-toolbtn:hover{ background: rgba(255,255,255,.08); }
        .wf2cc-seg button.sel{ background: rgba(13,110,253,.35); color:#fff; }
      }
    `;
    document.head.appendChild(style);

    const bar = document.createElement("div");
    bar.id = "wf2cc-toolbar";
    bar.className = "wf2cc-toolbar";
    bar.innerHTML = `
      <div class="wf2cc-seg" role="group" aria-label="Key visibility">
        <button type="button" id="wf2cc-mode-mand" data-mode="mandatory">Mandatory</button>
        <button type="button" id="wf2cc-mode-opt" data-mode="optional">Optional</button>
      </div>
      <button type="button" class="wf2cc-toolbtn" id="wf2cc-format-btn">Format</button>
    `;
    document.body.appendChild(bar);

    function sync() {
      const mand = bar.querySelector("#wf2cc-mode-mand");
      const opt = bar.querySelector("#wf2cc-mode-opt");
      mand.classList.toggle("sel", state.mode === "mandatory");
      opt.classList.toggle("sel", state.mode === "optional");
    }

    bar.querySelectorAll("[data-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.mode = btn.getAttribute("data-mode");
        sync();
        if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);
      });
    });

    bar.querySelector("#wf2cc-format-btn").addEventListener("click", async () => {
      const yamlEl = WF2CC.getYamlTextarea();
      if (!yamlEl) return;

      try {
        const formatted = await WF2CC.api.formatYaml(yamlEl.value);
        yamlEl.focus();
        yamlEl.value = formatted;
        yamlEl.dispatchEvent(new Event("input", { bubbles: true }));
        if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);
      } catch (err) {
        // Non-intrusive: show error in drawer if open, else alert
        const msg = err && err.message ? err.message : String(err);
        if (state.listEl) state.listEl.innerHTML = `<div class="wf2cc-error">${WF2CC.esc(msg)}</div>`;
        else alert(msg);
      }
    });

    // initial state
    sync();
  };
})();
