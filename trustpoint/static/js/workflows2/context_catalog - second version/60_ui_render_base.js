// static/js/workflows2/context_catalog/60_ui_render_base.js
(function () {
  const WF2CC = window.WF2CC;
  WF2CC.ui = WF2CC.ui || {};

  function setSelectedTab(state) {
    state.drawer.querySelectorAll(".wf2cc-tab").forEach((btn) => {
      const t = btn.getAttribute("data-tab");
      btn.classList.toggle("sel", t === state.tab);
    });
  }

  function groupify(items, getGroupKey) {
    const map = new Map();
    items.forEach((it) => {
      const g = getGroupKey(it) || "Other";
      if (!map.has(g)) map.set(g, []);
      map.get(g).push(it);
    });
    return [...map.entries()].map(([group, arr]) => ({ group, items: arr }));
  }

  function matchesQuery(q, ...fields) {
    if (!q) return true;
    const s = q.toLowerCase();
    return fields.some((f) => String(f || "").toLowerCase().includes(s));
  }

  function renderGroups(state, grouped) {
    const frag = document.createDocumentFragment();
    grouped.forEach((g) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "wf2cc-groupbtn" + (state.selectedGroup === g.group ? " sel" : "");
      btn.innerHTML = `<div style="display:flex; justify-content:space-between; gap:.5rem;">
        <span>${WF2CC.esc(g.group)}</span>
        <span style="opacity:.8;">${g.items.length}</span>
      </div>`;
      btn.addEventListener("click", () => {
        state.selectedGroup = g.group;
        state.manualGroup = true;
        WF2CC.render(state);
      });
      frag.appendChild(btn);
    });
    state.groupsEl.innerHTML = "";
    state.groupsEl.appendChild(frag);
  }

  function itemButtons() {
    return `
      <div style="display:flex; gap:.4rem; flex:0 0 auto;">
        <button type="button" class="btn btn-sm btn-primary" data-act="insert">Insert</button>
        <button type="button" class="btn btn-sm btn-outline-secondary" data-act="copy">Copy</button>
      </div>
    `;
  }

  function attachInsertCopyHandlers(row, { text, onInsert }) {
    const insertBtn = row.querySelector('[data-act="insert"]');
    const copyBtn = row.querySelector('[data-act="copy"]');

    if (insertBtn) {
      if (typeof onInsert === "function") {
        insertBtn.addEventListener("click", onInsert);
      } else {
        insertBtn.disabled = true;
        insertBtn.classList.add("disabled");
      }
    }

    if (copyBtn) {
      copyBtn.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(String(text || "")); } catch { /* ignore */ }
      });
    }
  }

  function currentEventSpec(state, triggerOn) {
    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    if (!triggerOn) return null;
    return events.find((e) => String(e.key) === String(triggerOn)) || null;
  }

  function shouldFilterByTrigger(ctx) {
    if (ctx.area === "trigger.on") return false;
    return !!ctx.triggerOn;
  }

  function filterAllowedStepTypes(state, ctx, steps) {
    if (state.mode === "optional") return steps;
    const ev = currentEventSpec(state, ctx.triggerOn);
    if (ev && Array.isArray(ev.allowed_step_types)) {
      return steps.filter((s) => ev.allowed_step_types.includes(s.type));
    }
    return steps;
  }

  function filterTemplates(state, ctx, presets) {
    if (state.mode === "optional") return presets;

    const allowedAreas = new Set([
      ctx.area,
      ctx.area.split(".").slice(0, 2).join("."),
      "root",
      "workflow",
      "apply",
      "trigger",
      "trigger.sources",
      "workflow.flow",
      "workflow.steps",
      "workflow.start",
    ]);

    const byArea = presets.filter((p) => (p.areas || []).some((a) => allowedAreas.has(a)));

    const byTrigger = shouldFilterByTrigger(ctx)
      ? byArea.filter((p) => !p.triggers || p.triggers.includes(ctx.triggerOn))
      : byArea;

    const byStep = ctx.stepType
      ? byTrigger.filter((p) => !p.step_types || p.step_types.includes(ctx.stepType))
      : byTrigger;

    return byStep;
  }

  function firstMeaningfulLine(snippet) {
    const lines = String(snippet || "").split("\n");
    for (const ln of lines) {
      if (String(ln || "").trim()) return String(ln);
    }
    return "";
  }

  function isListItemSnippet(snippet) {
    const ln = firstMeaningfulLine(snippet).trimStart();
    return ln.startsWith("- ");
  }

  function looksLikeMappingEntry(snippet) {
    const ln = firstMeaningfulLine(snippet).trimStart();
    return /^[A-Za-z_][A-Za-z0-9_]*\s*:/.test(ln);
  }

  function inferBlockIndent(ctx, snippet) {
    const area = String((ctx && ctx.area) || "");
    const ind = (ctx && ctx.indents) ? ctx.indents : {};

    // trigger.sources (keys vs list items)
    if (area.startsWith("trigger.sources")) {
      if (isListItemSnippet(snippet)) return ind.sourcesListItem ?? null;
      return ind.sourcesEntry ?? null;
    }

    // webhook.capture entries
    if (area === "workflow.steps.webhook.capture") {
      return ind.captureEntry ?? null;
    }

    // logic.cases block (usually list items)
    if (area === "workflow.steps.logic.cases") {
      return ind.casesItem ?? null;
    }

    // workflow steps: inserting fields should land at stepField indent
    if (area.startsWith("workflow.steps")) {
      // list item snippets inside certain blocks should not use stepField
      if (isListItemSnippet(snippet) && area.includes("cases")) return ind.casesItem ?? null;
      return ind.stepField ?? null;
    }

    if (area.startsWith("workflow.flow")) return ind.flowItem ?? null;
    if (area === "apply") return ind.applyItem ?? null;

    if (area.startsWith("trigger")) return ind.triggerChild ?? null;

    return null;
  }

  // Always insert into YAML textarea (catalog is for YAML).
  function getYamlTarget(state) {
    const yaml = WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;
    return yaml || (state.getInsertTarget ? state.getInsertTarget() : null);
  }

  function smartInsert(state, ctx, snippet, opts) {
    const el = getYamlTarget(state);
    if (!el) return false;

    const o = Object.assign({}, opts || {});
    const kind = String(o.kind || "inline");

    // Central policy: if it's a block insert and the renderer didn't specify baseIndent,
    // infer it from ctx.area so indentation is uniform.
    if (kind === "block") {
      const hasBaseIndent = Object.prototype.hasOwnProperty.call(o, "baseIndent") && o.baseIndent !== null && o.baseIndent !== undefined;

      if (!hasBaseIndent) {
        const inferred = inferBlockIndent(ctx, snippet);
        if (inferred !== null && inferred !== undefined) {
          o.baseIndent = inferred;
          o.indentToCursor = false;
        } else if (!Object.prototype.hasOwnProperty.call(o, "indentToCursor")) {
          // fallback: respect cursor indent if we can't infer
          o.indentToCursor = true;
        }
      }
    }

    return WF2CC.smartInsertByContext(el, snippet, ctx, o);
  }

  function replaceOnCurrentLine(state, ctx, newValue) {
    const yaml = WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;
    if (!yaml) return false;
    return WF2CC.replaceValueAfterColonOnLine(yaml, ctx.lineNo, newValue);
  }

  function preferGroup(state, grouped, preferred) {
    if (!preferred) return;
    if (state.manualGroup) return;
    if (grouped.some((g) => g.group === preferred)) state.selectedGroup = preferred;
  }

  WF2CC.ui._groupify = groupify;
  WF2CC.ui._matchesQuery = matchesQuery;
  WF2CC.ui._renderGroups = renderGroups;
  WF2CC.ui._itemButtons = itemButtons;
  WF2CC.ui._attachInsertCopyHandlers = attachInsertCopyHandlers;

  WF2CC.ui._currentEventSpec = currentEventSpec;
  WF2CC.ui._shouldFilterByTrigger = shouldFilterByTrigger;
  WF2CC.ui._filterAllowedStepTypes = filterAllowedStepTypes;
  WF2CC.ui._filterTemplates = filterTemplates;

  WF2CC.ui._smartInsert = smartInsert;
  WF2CC.ui._replaceOnCurrentLine = replaceOnCurrentLine;
  WF2CC.ui._preferGroup = preferGroup;

  WF2CC.ui.render = function render(state) {
    if (!state.drawer) return;

    setSelectedTab(state);

    const yamlEl = WF2CC.getYamlTextarea();
    const ctx = yamlEl
      ? WF2CC.getCursorContext(yamlEl.value, yamlEl.selectionStart ?? 0)
      : { triggerOn: null, area: "root", pill: "root", lineNo: 0, indents: {}, anchors: {}, varInsertMode: "template", stepIds: [] };

    state.ctx = ctx;
    state.pillEl.textContent = ctx.pill + (ctx.triggerOn ? `  |  trigger: ${ctx.triggerOn}` : "");

    if (state._lastArea !== ctx.area) {
      if (!state.manualGroup) state.selectedGroup = null;
      state._lastArea = ctx.area;
    }

    if (!state.manualTab && state.autoTab) {
      if (ctx.area === "expression" || ctx.varInsertMode === "vars_target") state.tab = "vars";
      else state.tab = "insert";
    }

    if (state._lastTab !== state.tab) {
      if (!state.manualGroup) state.selectedGroup = null;
      state._lastTab = state.tab;
    }

    if (state.tab === "vars") return WF2CC.ui.renderVars(state, ctx);
    return WF2CC.ui.renderInsert(state, ctx);
  };

  WF2CC.render = WF2CC.ui.render;
})();