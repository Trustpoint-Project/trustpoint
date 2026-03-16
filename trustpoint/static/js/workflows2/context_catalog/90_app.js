// static/js/workflows2/context_catalog/90_app.js
(function () {
  const WF2CC = window.WF2CC;

  const state = {
    drawer: null,
    searchEl: null,
    groupsEl: null,
    listEl: null,
    pillEl: null,

    catalog: { events: [], steps: [], presets: [] },
    sources: { cas: [], domains: [], devices: [] },

    tab: "insert",
    mode: "mandatory",
    selectedGroup: null,

    autoTab: true,
    manualTab: false,

    lastActiveField: null,

    undoStack: [],
    redoStack: [],
    _maxUndo: 200,

    getInsertTarget() {
      const yaml = WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;

      // Never allow drawer fields (search) to become insert targets.
      const el = this.lastActiveField;
      if (!el) return yaml;
      if (this.drawer && this.drawer.contains(el)) return yaml;

      // Only allow actual editor fields (textarea/input outside drawer).
      return el || yaml;
    },
  };

  function isTextField(el) {
    return el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT");
  }

  function snap(el) {
    return {
      value: String(el.value || ""),
      start: Number(el.selectionStart ?? 0),
      end: Number(el.selectionEnd ?? 0),
    };
  }

  function pushUndo(el) {
    if (!isTextField(el)) return;
    if (state.drawer && state.drawer.contains(el)) return; // never track undo for drawer inputs
    state.undoStack.push(snap(el));
    if (state.undoStack.length > state._maxUndo) state.undoStack.shift();
    state.redoStack.length = 0;
  }

  function applySnap(el, s) {
    el.value = s.value;
    el.focus();
    el.setSelectionRange(s.start, s.end);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);
  }

  function doUndo(el) {
    if (!state.undoStack.length) return false;
    const cur = snap(el);
    const prev = state.undoStack.pop();
    state.redoStack.push(cur);
    applySnap(el, prev);
    return true;
  }

  function doRedo(el) {
    if (!state.redoStack.length) return false;
    const cur = snap(el);
    const next = state.redoStack.pop();
    state.undoStack.push(cur);
    applySnap(el, next);
    return true;
  }

  function wrapUndoableEdits() {
    const original = {
      insertSmart: WF2CC.insertSmart,
      smartInsertByContext: WF2CC.smartInsertByContext,
      replaceWholeLine: WF2CC.replaceWholeLine,
      replaceValueAfterColonOnLine: WF2CC.replaceValueAfterColonOnLine,
      uiSmartInsert: WF2CC.ui && WF2CC.ui._smartInsert,
      uiReplaceOnCurrentLine: WF2CC.ui && WF2CC.ui._replaceOnCurrentLine,
    };

    function currentLineInfo(el) {
      const text = String(el.value || "");
      const pos = Number(el.selectionStart ?? 0);
      const lines = text.split("\n");
      let acc = 0;
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        const start = acc;
        const end = acc + line.length;
        if (pos >= start && pos <= end) {
          return { lineNo: i, lineText: line, lineStartIdx: start, lineEndIdx: end };
        }
        acc = end + 1;
      }
      return { lineNo: 0, lineText: lines[0] || "", lineStartIdx: 0, lineEndIdx: (lines[0] || "").length };
    }

    function shouldReuseBlankLine(snippet, opts) {
      const kind = opts && opts.kind;
      return kind === "block" || String(snippet || "").includes("\n");
    }

    function applyCursorToken(snippet) {
      let s = String(snippet || "");
      let caret = null;

      const idx = s.indexOf("__CURSOR__");
      if (idx !== -1) {
        caret = idx;
        if (caret > 0 && s[caret - 1] === "/") {
          s = s.slice(0, caret - 1) + s.slice(caret);
          caret = caret - 1;
        }
        s = s.replace("__CURSOR__", "");
      }

      return { text: s, caretOffsetInSnippet: caret };
    }

    function insertReplacingBlankLine(el, snippet) {
      const info = currentLineInfo(el);
      const isBlank = !String(info.lineText || "").trim();
      if (!isBlank) return false;

      pushUndo(el);

      const lines = String(el.value || "").split("\n");
      const processed = applyCursorToken(snippet);
      lines[info.lineNo] = processed.text;

      el.value = lines.join("\n");
      el.focus();

      let idx = 0;
      for (let i = 0; i < info.lineNo; i += 1) idx += lines[i].length + 1;
      if (processed.caretOffsetInSnippet != null) idx += processed.caretOffsetInSnippet;

      el.setSelectionRange(idx, idx);
      el.dispatchEvent(new Event("input", { bubbles: true }));
      if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);

      if (WF2CC.folding && typeof WF2CC.folding.refresh === "function") WF2CC.folding.refresh();
      return true;
    }

    if (typeof original.insertSmart === "function") {
      WF2CC.insertSmart = function (el, text, opts) {
        if (el && shouldReuseBlankLine(text, opts)) {
          const did = insertReplacingBlankLine(el, text);
          if (did) return;
        }
        pushUndo(el);
        return original.insertSmart.call(this, el, text, opts);
      };
    }

    if (typeof original.smartInsertByContext === "function") {
      WF2CC.smartInsertByContext = function (el, snippet, ctx, opts) {
        if (el && shouldReuseBlankLine(snippet, opts)) {
          const did = insertReplacingBlankLine(el, snippet);
          if (did) return;
        }
        pushUndo(el);
        return original.smartInsertByContext.call(this, el, snippet, ctx, opts);
      };
    }

    if (typeof original.replaceWholeLine === "function") {
      WF2CC.replaceWholeLine = function (el, lineNo, newLine) {
        pushUndo(el);
        return original.replaceWholeLine.call(this, el, lineNo, newLine);
      };
    }

    if (typeof original.replaceValueAfterColonOnLine === "function") {
      WF2CC.replaceValueAfterColonOnLine = function (el, lineNo, newValue) {
        pushUndo(el);
        return original.replaceValueAfterColonOnLine.call(this, el, lineNo, newValue);
      };
    }

    if (WF2CC.ui && typeof original.uiSmartInsert === "function") {
      WF2CC.ui._smartInsert = function (stateArg, ctxArg, snippet, opts) {
        const el = stateArg && stateArg.getInsertTarget ? stateArg.getInsertTarget() : WF2CC.getYamlTextarea();
        if (el && shouldReuseBlankLine(snippet, opts)) {
          const did = insertReplacingBlankLine(el, snippet);
          if (did) return;
        }
        pushUndo(el);
        return original.uiSmartInsert.call(this, stateArg, ctxArg, snippet, opts);
      };
    }

    if (WF2CC.ui && typeof original.uiReplaceOnCurrentLine === "function") {
      WF2CC.ui._replaceOnCurrentLine = function (stateArg, ctxArg, newValue) {
        const el = stateArg && stateArg.getInsertTarget ? stateArg.getInsertTarget() : WF2CC.getYamlTextarea();
        pushUndo(el);
        return original.uiReplaceOnCurrentLine.call(this, stateArg, ctxArg, newValue);
      };
    }
  }

  // Focus tracking: ONLY track fields outside the drawer.
  document.addEventListener("focusin", (e) => {
    const el = e.target;
    if (!isTextField(el)) return;

    // Never treat drawer inputs (search etc.) as active insert targets.
    if (state.drawer && state.drawer.contains(el)) return;

    state.lastActiveField = el;
    if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);
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
      border: 1px solid var(--bs-border-color, rgba(0,0,0,.15));
      background: var(--bs-body-bg, #fff); color: var(--bs-body-color, #111);
      cursor: pointer; user-select: none; font-size: .9rem;
      box-shadow: 0 6px 18px rgba(0,0,0,.14);
    `;
    fab.innerHTML = `Catalog <span style="opacity:.75;font-size:.8rem;">Ctrl/⌘+K</span>`;
    fab.addEventListener("click", () => WF2CC.toggle(state));
    document.body.appendChild(fab);
  }

  function bindFormatButton() {
    const btn = document.getElementById("wf2-format-yaml");
    if (!btn) return;

    btn.addEventListener("click", async () => {
      const yamlEl = WF2CC.getYamlTextarea();
      if (!yamlEl) return;

      try {
        if (WF2CC.folding && typeof WF2CC.folding.expandAll === "function") {
          WF2CC.folding.expandAll();
        }

        const formatted = await WF2CC.api.formatYaml(yamlEl.value);

        yamlEl.focus();
        yamlEl.value = formatted;
        yamlEl.dispatchEvent(new Event("input", { bubbles: true }));

        if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);
        if (WF2CC.folding && typeof WF2CC.folding.refresh === "function") WF2CC.folding.refresh();
      } catch (err) {
        const msg = err && err.message ? err.message : String(err);
        alert(msg);
      }
    });
  }

  async function init() {
    WF2CC.ensureDrawer(state);
    createFabIfMissing();
    bindFormatButton();

    wrapUndoableEdits();

    const yamlEl = WF2CC.getYamlTextarea();
    if (yamlEl) {
      WF2CC.enableTextareaIndent(yamlEl);

      if (WF2CC.folding && typeof WF2CC.folding.init === "function") {
        WF2CC.folding.init(yamlEl);
      }

      const form = document.getElementById("wf2-form");
      if (form && WF2CC.folding && typeof WF2CC.folding.expandAll === "function") {
        form.addEventListener("submit", () => WF2CC.folding.expandAll());
      }
    }

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

      if (state.drawer && state.drawer.classList.contains("open")) {
        const target = state.getInsertTarget() || WF2CC.getYamlTextarea();
        if (!isTextField(target)) return;

        const isUndo = (e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && k === "z";
        const isRedo = (e.ctrlKey && !e.shiftKey && !e.altKey && k === "y")
          || ((e.metaKey || e.ctrlKey) && e.shiftKey && !e.altKey && k === "z");

        if (isUndo) {
          e.preventDefault();
          if (!doUndo(target)) {
            target.focus();
            document.execCommand("undo");
          }
          return;
        }

        if (isRedo) {
          e.preventDefault();
          if (!doRedo(target)) {
            target.focus();
            document.execCommand("redo");
          }
          return;
        }
      }
    });

    const rer = WF2CC.debounce(() => {
      if (state.drawer && state.drawer.classList.contains("open")) WF2CC.render(state);
      if (WF2CC.folding && typeof WF2CC.folding.refresh === "function") WF2CC.folding.refresh();
    }, 80);

    if (yamlEl) {
      yamlEl.addEventListener("input", rer);
      yamlEl.addEventListener("click", rer);
      yamlEl.addEventListener("keyup", rer);
      yamlEl.addEventListener("scroll", () => {
        if (WF2CC.folding && typeof WF2CC.folding.refresh === "function") WF2CC.folding.refresh();
      });
    }

    document.addEventListener("selectionchange", () => {
      const active = document.activeElement;
      if (!active) return;
      const yaml = WF2CC.getYamlTextarea();
      if (yaml && active === yaml) rer();
    });

    try {
      state.catalog = await WF2CC.loadCatalog();
      if (typeof WF2CC.loadSources === "function") {
        try { state.sources = await WF2CC.loadSources(); }
        catch { state.sources = { cas: [], domains: [], devices: [] }; }
      }
      WF2CC.render(state);
      if (WF2CC.folding && typeof WF2CC.folding.refresh === "function") WF2CC.folding.refresh();
    } catch (err) {
      state.catalog = { events: [], steps: [], presets: [] };
      state.sources = { cas: [], domains: [], devices: [] };
      state.groupsEl.innerHTML = `<div class="wf2cc-error">${WF2CC.esc(err && err.stack ? err.stack : String(err))}</div>`;
      state.listEl.innerHTML = `<div class="wf2cc-empty">Failed to load context catalog.</div>`;
    }
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();