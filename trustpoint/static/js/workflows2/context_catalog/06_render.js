// static/js/workflows2/context_catalog/06_render.js
(function () {
  const WF2CC = window.WF2CC;

  function setSelectedTab(state) {
    state.drawer.querySelectorAll(".wf2cc-tab").forEach((btn) => {
      const t = btn.getAttribute("data-tab");
      btn.classList.toggle("sel", t === state.tab);
    });
    state.drawer.querySelector("#wf2cc-mode-allowed").classList.toggle("active", state.mode === "allowed");
    state.drawer.querySelector("#wf2cc-mode-all").classList.toggle("active", state.mode === "all");
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
        state.manualGroup = true; // user explicitly chose
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

    insertBtn.addEventListener("click", onInsert);
    copyBtn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(text); } catch { /* ignore */ }
    });
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
    if (state.mode === "all") return steps;
    const ev = currentEventSpec(state, ctx.triggerOn);
    if (ev && Array.isArray(ev.allowed_step_types)) {
      return steps.filter((s) => ev.allowed_step_types.includes(s.type));
    }
    return steps;
  }

  function filterTemplates(state, ctx, presets) {
    if (state.mode === "all") return presets;

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

  function getVarItems(state, ctx) {
    if (ctx.varInsertMode === "vars_target") {
      return [
        { path: "vars.__CURSOR__", description: "vars.<name> (capture target)", type: "vars-target" },
        { path: "vars.http_status", description: "vars.http_status (example)", type: "vars-target" },
        { path: "vars.http_body", description: "vars.http_body (example)", type: "vars-target" },
      ];
    }

    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    const candidates = shouldFilterByTrigger(ctx) && ctx.triggerOn
      ? events.filter((e) => String(e.key) === String(ctx.triggerOn))
      : events;

    const map = new Map();
    candidates.forEach((e) => {
      (e.context_vars || []).forEach((v) => {
        if (!v || !v.path) return;
        if (!map.has(v.path)) map.set(v.path, v);
      });
    });

    return [...map.values()];
  }

  function smartInsert(state, ctx, snippet, opts) {
    const el = state.getInsertTarget();
    return WF2CC.smartInsertByContext(el, snippet, ctx, opts);
  }

  function replaceOnCurrentLine(state, ctx, newValue) {
    const el = state.getInsertTarget();
    return WF2CC.replaceValueAfterColonOnLine(el, ctx.lineNo, newValue);
  }

  // ---------------- Vars tab ----------------

  function renderVars(state, ctx) {
    const q = (state.searchEl.value || "").trim();
    const items = getVarItems(state, ctx).filter((v) => matchesQuery(q, v.path, v.description, v.type));

    const grouped = groupify(items, (v) => String(v.path || "").split(".")[0] || "misc");
    if (!state.selectedGroup) state.selectedGroup = grouped[0]?.group || null;
    if (state.selectedGroup && !grouped.some((g) => g.group === state.selectedGroup)) state.selectedGroup = grouped[0]?.group || null;
    renderGroups(state, grouped);

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    if (!current || !current.items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No matches.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();
    current.items.forEach((v) => {
      const insertText = WF2CC.formatVarInsert(ctx, v.path);

      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(v.description || v.path)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(insertText)}</div>
        </div>
        ${itemButtons()}
      `;

      attachInsertCopyHandlers(row, {
        text: insertText,
        onInsert: () => {
          const el = state.getInsertTarget();
          WF2CC.insertSmart(el, insertText, { kind: "inline" });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  // ---------------- Insert tab helpers ----------------

  function preferGroup(state, grouped, preferred) {
    if (!preferred) return;
    if (state.manualGroup) return;
    if (grouped.some((g) => g.group === preferred)) {
      state.selectedGroup = preferred;
    }
  }

  function renderInsertTemplates(state, ctx, areasHint) {
    const presets = Array.isArray(state.catalog.presets) ? state.catalog.presets : [];
    const q = (state.searchEl.value || "").trim();

    const filtered = filterTemplates(state, ctx, presets)
      .filter((p) => matchesQuery(q, p.title, p.description, p.id));

    // IMPORTANT: do NOT default group to first encountered (often "root")
    // Group by first area for stability
    const grouped = groupify(filtered, (p) => ((p.areas && p.areas[0]) || "misc"));

    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }
    preferGroup(state, grouped, areasHint);

    renderGroups(state, grouped);

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    if (!current || !current.items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No templates available here.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();

    current.items.forEach((p) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(p.title)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(p.description || "")}</div>
        </div>
        ${itemButtons()}
      `;

      attachInsertCopyHandlers(row, {
        text: p.snippet,
        onInsert: () => {
          const yamlEl = WF2CC.getYamlTextarea();

          // If apply is inline [] convert it first
          if ((p.areas || []).includes("apply") && ctx.applyInlineList && typeof ctx.applyLineNo === "number") {
            WF2CC.replaceWholeLine(yamlEl, ctx.applyLineNo, "apply:");
          }

          // If flow is inline [] convert it first
          if ((p.areas || []).includes("workflow.flow") && ctx.flowInlineList && typeof ctx.flowLineNo === "number") {
            WF2CC.replaceWholeLine(yamlEl, ctx.flowLineNo, "  flow:");
          }

          let anchor = "cursor";
          let baseIndent = null;

          // key: choose correct anchors + indents
          if ((p.areas || []).includes("workflow.flow")) {
            anchor = "flow_end";
            baseIndent = ctx.indents.flowItem;
          } else if ((p.areas || []).includes("workflow.steps")) {
            anchor = "steps_end";
            baseIndent = ctx.indents.stepItem;
          } else if ((p.areas || []).includes("workflow.start")) {
            anchor = "workflow_head";      // inside workflow:
            baseIndent = ctx.indents.wfChild;
          } else if ((p.areas || []).includes("apply")) {
            anchor = "apply_end";
            baseIndent = ctx.indents.applyItem;
          } else if ((p.areas || []).includes("trigger.sources")) {
            anchor = "sources_end";
            baseIndent = ctx.indents.sourcesEntry;
          } else if ((p.areas || []).includes("trigger")) {
            anchor = "trigger_end";
            baseIndent = ctx.indents.triggerChild;
          }

          smartInsert(state, ctx, p.snippet, {
            kind: p.insert_kind === "block" ? "block" : "inline",
            ensureNewline: false, // prevents double blank lines at anchors
            anchor,
            baseIndent,
          });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function renderInsertTriggers(state, ctx) {
    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    const q = (state.searchEl.value || "").trim();
    const filtered = events.filter((e) => matchesQuery(q, e.key, e.description, e.group));

    const grouped = groupify(filtered, (e) => e.group || "Other");
    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }
    renderGroups(state, grouped);

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    if (!current || !current.items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No triggers found.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();
    current.items.forEach((e) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(e.key)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(e.description || "")}</div>
        </div>
        ${itemButtons()}
      `;

      attachInsertCopyHandlers(row, {
        text: e.key,
        onInsert: () => {
          if (ctx.area === "trigger.on") replaceOnCurrentLine(state, ctx, e.key);
          else WF2CC.insertSmart(state.getInsertTarget(), e.key, { kind: "inline" });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function renderInsertSteps(state, ctx) {
    const steps = Array.isArray(state.catalog.steps) ? state.catalog.steps : [];
    const q = (state.searchEl.value || "").trim();

    const allowed = filterAllowedStepTypes(state, ctx, steps);
    const filtered = allowed.filter((s) => matchesQuery(q, s.type, s.title, s.description, s.category));

    const grouped = groupify(filtered, (s) => (s.category === "terminal" ? "Terminal" : "Steps"));

    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }
    renderGroups(state, grouped);

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    if (!current || !current.items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No steps found.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();

    current.items.forEach((s) => {
      // If inside step, show fields
      if (state.mode === "allowed" && ctx.stepType === s.type && Array.isArray(s.fields) && s.fields.length) {
        s.fields.forEach((f) => {
          const row = document.createElement("div");
          row.className = "wf2cc-item";
          row.innerHTML = `
            <div style="min-width:0;">
              <div style="font-weight:600;">${WF2CC.esc(s.type)} · ${WF2CC.esc(f.title)}</div>
              <div class="wf2cc-sub">${WF2CC.esc(f.description || "")}</div>
            </div>
            ${itemButtons()}
          `;

          let anchor = "step_end";
          let baseIndent = ctx.indents.stepField;

          if (ctx.area === "workflow.steps.webhook.capture") {
            anchor = "capture_end";
            baseIndent = ctx.indents.captureEntry;
          }
          if (ctx.area === "workflow.steps.logic.cases") {
            anchor = "cases_end";
            baseIndent = ctx.indents.casesItem;
          }

          attachInsertCopyHandlers(row, {
            text: f.snippet,
            onInsert: () => {
              smartInsert(state, ctx, f.snippet, {
                kind: f.insert_kind === "block" ? "block" : "inline",
                ensureNewline: false,
                anchor,
                baseIndent,
              });
            },
          });

          frag.appendChild(row);
        });
        return;
      }

      // Insert new step skeleton at steps end
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(s.title || s.type)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(s.type)} · ${WF2CC.esc(s.description || "")}</div>
        </div>
        ${itemButtons()}
      `;

      attachInsertCopyHandlers(row, {
        text: s.block_snippet,
        onInsert: () => {
          smartInsert(state, ctx, s.block_snippet, {
            kind: "block",
            ensureNewline: false,
            anchor: "steps_end",
            baseIndent: ctx.indents.stepItem,
          });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function renderInsertStepIdPicker(state, ctx) {
    const q = (state.searchEl.value || "").trim();
    const ids = Array.isArray(ctx.stepIds) ? ctx.stepIds : [];

    const items = ids.filter((id) => matchesQuery(q, id)).map((id) => ({ group: "Step IDs", id }));
    const grouped = groupify(items, (x) => x.group);

    state.selectedGroup = "Step IDs";
    renderGroups(state, grouped);

    const frag = document.createDocumentFragment();
    items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(it.id)}</div>
          <div class="wf2cc-sub">Insert existing step id</div>
        </div>
        ${itemButtons()}
      `;

      attachInsertCopyHandlers(row, {
        text: it.id,
        onInsert: () => replaceOnCurrentLine(state, ctx, it.id),
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function renderInsert(state, ctx) {
    if (ctx.area === "trigger.on") return renderInsertTriggers(state, ctx);
    if (ctx.area === "trigger.sources") return renderInsertTemplates(state, ctx, "trigger.sources");
    if (ctx.area.startsWith("trigger")) return renderInsertTemplates(state, ctx, "trigger");

    if (ctx.area === "apply") return renderInsertTemplates(state, ctx, "apply");

    if (ctx.area === "workflow.start") return renderInsertStepIdPicker(state, ctx);
    if (ctx.area === "workflow.flow.from" || ctx.area === "workflow.flow.to") return renderInsertStepIdPicker(state, ctx);
    if (ctx.area.startsWith("workflow.flow")) return renderInsertTemplates(state, ctx, "workflow.flow");

    if (ctx.area.startsWith("workflow.steps")) return renderInsertSteps(state, ctx);

    return renderInsertTemplates(state, ctx, "root");
  }

  // ---------------- main render ----------------

  WF2CC.render = function render(state) {
    if (!state.drawer) return;

    setSelectedTab(state);

    const yamlEl = WF2CC.getYamlTextarea();
    const ctx = yamlEl
      ? WF2CC.getCursorContext(yamlEl.value, yamlEl.selectionStart ?? 0)
      : { triggerOn: null, area: "root", pill: "root", lineNo: 0, indents: {}, anchors: {}, varInsertMode: "template", stepIds: [] };

    state.ctx = ctx;
    state.pillEl.textContent = ctx.pill + (ctx.triggerOn ? `  |  trigger: ${ctx.triggerOn}` : "");

    // If cursor area changed and user didn’t manually pick a group: reset group to allow auto-selection
    if (state._lastArea !== ctx.area) {
      if (!state.manualGroup) state.selectedGroup = null;
      state._lastArea = ctx.area;
    }

    if (!state.manualTab && state.autoTab) {
      if (ctx.area === "expression" || ctx.varInsertMode === "vars_target") state.tab = "vars";
      else state.tab = "insert";
    }

    const q = (state.searchEl.value || "").trim();
    if (q) {
      // keep your current global search behavior as-is (optional later)
      // for now, just render insert/templates with filtering; vars tab already filters
    }

    if (state._lastTab !== state.tab) {
      if (!state.manualGroup) state.selectedGroup = null;
      state._lastTab = state.tab;
    }

    if (state.tab === "vars") return renderVars(state, ctx);
    return renderInsert(state, ctx);
  };
})();
