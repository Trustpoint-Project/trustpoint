// static/js/workflows2/context_catalog/50_ui_drawer.js
(function () {
  const WF2CC = window.WF2CC;

  WF2CC.ui.ensureDrawer = function ensureDrawer(state) {
    if (state.drawer) return;

    const style = document.createElement("style");
    style.textContent = `
      .wf2cc-drawer{
        position:fixed; top:0; right:0;
        width: 620px; max-width: 96vw; height:100vh;
        background: var(--bs-body-bg, #fff);
        color: var(--bs-body-color, #111);
        border-left:1px solid var(--bs-border-color, rgba(0,0,0,.12));
        box-shadow:-6px 0 16px rgba(0,0,0,.12);
        z-index:2100; display:none; flex-direction:column;
      }
      .wf2cc-drawer.open{ display:flex; }
      .wf2cc-head{
        display:flex; align-items:center; justify-content:space-between;
        padding:.55rem .75rem;
        border-bottom:1px solid var(--bs-border-color, rgba(0,0,0,.12));
      }
      .wf2cc-title{ font-weight:600; display:flex; flex-direction:column; gap:.15rem; }
      .wf2cc-pill{ font-size:.75rem; opacity:.85; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }

      .wf2cc-tabs{
        display:flex; gap:.35rem; padding:.5rem .75rem;
        border-bottom:1px solid var(--bs-border-color, rgba(0,0,0,.12));
      }
      .wf2cc-tab{
        background:transparent;
        border:1px solid var(--bs-border-color, rgba(0,0,0,.18));
        color:inherit; padding:.25rem .55rem; border-radius:.5rem; cursor:pointer;
      }
      .wf2cc-tab.sel{ background: rgba(13,110,253,.12); border-color: rgba(13,110,253,.28); }

      .wf2cc-body{ padding:.5rem .75rem; display:flex; flex-direction:column; gap:.5rem; overflow:hidden; }
      .wf2cc-row{ display:flex; gap:.5rem; align-items:center; flex-wrap:wrap; }
      .wf2cc-split{ flex:1 1 auto; min-height:0; display:flex; gap:.5rem; overflow:hidden; }
      .wf2cc-groups{
        flex:0 0 220px; overflow:auto;
        border:1px solid var(--bs-border-color, rgba(0,0,0,.12));
        border-radius:.6rem;
        background: rgba(0,0,0,.02); padding:.25rem;
      }
      .wf2cc-list{ flex:1 1 auto; overflow:auto; padding-bottom:0rem; }

      .wf2cc-groupbtn{
        width:100%; text-align:left;
        border:1px solid transparent;
        background:transparent; color:inherit;
        padding:.35rem .4rem; border-radius:.45rem; margin-bottom:.25rem; cursor:pointer;
      }
      .wf2cc-groupbtn:hover{ background: rgba(0,0,0,.05); border-color: rgba(0,0,0,.08); }
      .wf2cc-groupbtn.sel{ background: rgba(13,110,253,.12); border-color: rgba(13,110,253,.28); }

      .wf2cc-item{
        display:flex; align-items:center; justify-content:space-between; gap:.5rem; padding:.5rem;
        border:1px solid var(--bs-border-color, rgba(0,0,0,.12));
        border-radius:.6rem; background: rgba(0,0,0,.01); margin-bottom:.5rem;
      }
      .wf2cc-sub{
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size:.8rem; color: var(--bs-secondary-color, rgba(0,0,0,.6));
        word-break: break-word;
      }
      .wf2cc-empty{ padding:.5rem; color: var(--bs-secondary-color, rgba(0,0,0,.6)); font-size:.9rem; }
      .wf2cc-error{
        padding:.5rem; border:1px solid rgba(220,53,69,.35); border-radius:.6rem; background: rgba(220,53,69,.08);
        white-space:pre-wrap; word-break:break-word;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      }

      .wf2cc-seg{
        display:flex; align-items:center;
        border:1px solid var(--bs-border-color, rgba(0,0,0,.18));
        border-radius: 999px; overflow:hidden;
      }
      .wf2cc-seg button{
        border:0; background:transparent; color:inherit;
        padding:.25rem .6rem; font-size:.85rem; cursor:pointer;
      }
      .wf2cc-seg button.sel{
        background: rgba(13,110,253,.12);
        font-weight:600;
      }

      body.wf2cc-open .tp-main { margin-right: 640px; }
      @media (max-width: 991px) { body.wf2cc-open .tp-main { margin-right: 0; } }
    `;
    document.head.appendChild(style);

    const drawer = document.createElement("div");
    drawer.className = "wf2cc-drawer";
    drawer.innerHTML = `
      <div class="wf2cc-head">
        <div class="wf2cc-title">
          <div>Context catalog</div>
          <div class="wf2cc-pill" id="wf2cc-pill">root</div>
        </div>
        <button type="button" class="btn btn-sm btn-outline-secondary" id="wf2cc-close">×</button>
      </div>

      <div class="wf2cc-tabs">
        <button type="button" class="wf2cc-tab" data-tab="insert">Insert</button>
        <button type="button" class="wf2cc-tab" data-tab="vars">Vars</button>
      </div>

      <div class="wf2cc-body">
        <div class="wf2cc-row">
          <input type="search" class="form-control form-control-sm" id="wf2cc-search"
            placeholder="Search inserts + vars..." />

          <div class="wf2cc-seg" role="group" aria-label="Field visibility">
            <button type="button" id="wf2cc-mode-mand" data-mode="mandatory">Required</button>
            <button type="button" id="wf2cc-mode-opt" data-mode="optional">Extras</button>
          </div>

          <button type="button" class="btn btn-sm btn-outline-secondary" id="wf2cc-auto">Auto</button>
        </div>

        <div class="wf2cc-split">
          <div class="wf2cc-groups" id="wf2cc-groups"></div>
          <div class="wf2cc-list" id="wf2cc-list"></div>
        </div>
      </div>
    `;
    document.body.appendChild(drawer);

    state.drawer = drawer;
    state.searchEl = drawer.querySelector("#wf2cc-search");
    state.groupsEl = drawer.querySelector("#wf2cc-groups");
    state.listEl = drawer.querySelector("#wf2cc-list");
    state.pillEl = drawer.querySelector("#wf2cc-pill");

    drawer.querySelector("#wf2cc-close").addEventListener("click", () => WF2CC.close(state));

    drawer.querySelectorAll(".wf2cc-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.tab = btn.getAttribute("data-tab");
        state.manualTab = true;
        WF2CC.render(state);
      });
    });

    function syncModeButtons() {
      const mand = drawer.querySelector("#wf2cc-mode-mand");
      const opt = drawer.querySelector("#wf2cc-mode-opt");
      mand.classList.toggle("sel", state.mode === "mandatory");
      opt.classList.toggle("sel", state.mode === "optional");
    }

    drawer.querySelectorAll("[data-mode]").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.mode = btn.getAttribute("data-mode");
        syncModeButtons();
        WF2CC.render(state);
      });
    });

    drawer.querySelector("#wf2cc-auto").addEventListener("click", () => {
      state.manualTab = false;
      state.autoTab = true;
      WF2CC.render(state);
    });

    state.searchEl.addEventListener("input", WF2CC.debounce(() => WF2CC.render(state), 60));

    if (!state.mode) state.mode = "mandatory";
    syncModeButtons();
  };

  WF2CC.ui.open = function open(state) {
    WF2CC.ui.ensureDrawer(state);
    state.drawer.classList.add("open");
    document.body.classList.add("wf2cc-open");

    state.manualTab = false;
    state.autoTab = true;

    // ✅ DO NOT focus search (it breaks cursor context + insert target).
    // Keep focus in YAML editor; user can click search when needed.
    WF2CC.render(state);
  };

  WF2CC.ui.close = function close(state) {
    if (!state.drawer) return;
    state.drawer.classList.remove("open");
    document.body.classList.remove("wf2cc-open");
  };

  WF2CC.ui.toggle = function toggle(state) {
    WF2CC.ui.ensureDrawer(state);
    if (state.drawer.classList.contains("open")) WF2CC.close(state);
    else WF2CC.open(state);
  };

  WF2CC.ensureDrawer = WF2CC.ui.ensureDrawer;
  WF2CC.open = WF2CC.ui.open;
  WF2CC.close = WF2CC.ui.close;
  WF2CC.toggle = WF2CC.ui.toggle;
})();