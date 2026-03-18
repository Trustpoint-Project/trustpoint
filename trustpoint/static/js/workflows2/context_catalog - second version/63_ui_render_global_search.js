// static/js/workflows2/context_catalog/63_ui_render_global_search.js
(function () {
  const WF2CC = window.WF2CC;

  function getYamlEl() {
    return WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;
  }

  function getAllVars(state) {
    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    const map = new Map();
    events.forEach((e) => {
      (e.context_vars || []).forEach((v) => {
        if (!v || !v.path) return;
        if (!map.has(v.path)) map.set(v.path, v);
      });
    });
    return [...map.values()];
  }

  // Global search: don't area-filter templates,
  // but ALWAYS keep trigger + step-type restrictions.
  function globalFilterTemplates(state, ctx, presets) {
    const byTrigger = (WF2CC.ui._shouldFilterByTrigger(ctx) && ctx.triggerOn)
      ? presets.filter((p) => !p.triggers || p.triggers.includes(ctx.triggerOn))
      : presets;

    const byStep = ctx.stepType
      ? byTrigger.filter((p) => !p.step_types || p.step_types.includes(ctx.stepType))
      : byTrigger;

    return byStep;
  }

  function insertTemplate(state, ctx, p) {
    const yamlEl = getYamlEl();
    if (!yamlEl) return;

    // Expand inline placeholders
    if ((p.areas || []).includes("apply") && ctx.applyInlineList && typeof ctx.applyLineNo === "number") {
      WF2CC.replaceWholeLine(yamlEl, ctx.applyLineNo, "apply:");
    }
    if ((p.areas || []).includes("workflow.flow") && ctx.flowInlineList && typeof ctx.flowLineNo === "number") {
      WF2CC.replaceWholeLine(yamlEl, ctx.flowLineNo, "  flow:");
    }

    let anchor = "cursor";
    let baseIndent = null;

    if ((p.areas || []).includes("workflow.flow")) {
      anchor = "flow_end";
      baseIndent = ctx.indents.flowItem;
    } else if ((p.areas || []).includes("workflow.steps")) {
      anchor = "steps_end";
      baseIndent = ctx.indents.stepItem;
    } else if ((p.areas || []).includes("workflow.start")) {
      anchor = "workflow_head";
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

    WF2CC.ui._smartInsert(state, ctx, p.snippet, {
      kind: p.insert_kind === "block" ? "block" : "inline",
      ensureNewline: false,
      anchor,
      baseIndent,
    });
  }

  function insertStepBlock(state, ctx, s) {
    WF2CC.ui._smartInsert(state, ctx, s.block_snippet, {
      kind: "block",
      ensureNewline: false,
      anchor: "steps_end",
      baseIndent: ctx.indents.stepItem,
      indentToCursor: false,
    });
  }

  function insertStepField(state, ctx, stepType, f) {
    // For global search, we insert relative to the current cursor context.
    // If you're in capture/cases areas, route there; otherwise insert near cursor line.
    let anchor = "cursor_line_next";
    let baseIndent = null;

    if (String(ctx.area || "") === "workflow.steps.webhook.capture") {
      anchor = "capture_end";
      baseIndent = ctx.indents.captureEntry;
    } else if (String(ctx.area || "") === "workflow.steps.logic.cases") {
      anchor = "cases_end";
      baseIndent = ctx.indents.casesItem;
    } else if (String(ctx.area || "").startsWith("workflow.steps")) {
      // inside a step: fields belong at stepField indent
      baseIndent = ctx.indents.stepField;
    }

    WF2CC.ui._smartInsert(state, ctx, String(f.snippet || ""), {
      kind: f.insert_kind === "block" ? "block" : "inline",
      ensureNewline: false,
      anchor,
      baseIndent,
    });
  }

  function insertTrigger(state, ctx, key) {
    const yamlEl = getYamlEl();
    if (!yamlEl) return;

    if (ctx.area === "trigger.on") {
      WF2CC.ui._replaceOnCurrentLine(state, ctx, key);
      return;
    }
    WF2CC.insertSmart(yamlEl, key, { kind: "inline" });
  }

  function insertVar(state, ctx, path) {
    const yamlEl = getYamlEl();
    if (!yamlEl) return;

    const insertText = WF2CC.formatVarInsert(ctx, path);
    WF2CC.insertSmart(yamlEl, insertText, { kind: "inline" });
  }

  function insertStepId(state, ctx, id) {
    const yamlEl = getYamlEl();
    if (!yamlEl) return;

    if (ctx.area === "workflow.start" || ctx.area === "workflow.flow.from" || ctx.area === "workflow.flow.to") {
      WF2CC.ui._replaceOnCurrentLine(state, ctx, id);
      return;
    }
    WF2CC.insertSmart(yamlEl, id, { kind: "inline" });
  }

  function renderGlobalGroup(state, ctx, groupName, items) {
    if (!items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No matches.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();

    items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";

      if (groupName === "Templates") {
        const p = it;
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(p.title)}</div>
            <div class="wf2cc-sub">${WF2CC.esc(p.description || "")}</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;
        WF2CC.ui._attachInsertCopyHandlers(row, { text: p.snippet, onInsert: () => insertTemplate(state, ctx, p) });
        frag.appendChild(row);
        return;
      }

      if (groupName === "Steps") {
        const s = it;
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(s.title || s.type)}</div>
            <div class="wf2cc-sub">${WF2CC.esc(s.type)} · ${WF2CC.esc(s.description || "")}</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;
        WF2CC.ui._attachInsertCopyHandlers(row, { text: s.block_snippet, onInsert: () => insertStepBlock(state, ctx, s) });
        frag.appendChild(row);
        return;
      }

      if (groupName === "Fields") {
        const x = it;
        const f = x.field;
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(x.stepType)} · ${WF2CC.esc(f.title)}</div>
            <div class="wf2cc-sub">${WF2CC.esc(f.description || "")}</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;
        WF2CC.ui._attachInsertCopyHandlers(row, {
          text: f.snippet,
          onInsert: () => insertStepField(state, ctx, x.stepType, f),
        });
        frag.appendChild(row);
        return;
      }

      if (groupName === "Triggers") {
        const e = it;
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(e.key)}</div>
            <div class="wf2cc-sub">${WF2CC.esc(e.description || "")}</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;
        WF2CC.ui._attachInsertCopyHandlers(row, { text: e.key, onInsert: () => insertTrigger(state, ctx, e.key) });
        frag.appendChild(row);
        return;
      }

      if (groupName === "Vars") {
        const v = it;
        const insertText = WF2CC.formatVarInsert(ctx, v.path);
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(v.description || v.path)}</div>
            <div class="wf2cc-sub">${WF2CC.esc(insertText)}</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;
        WF2CC.ui._attachInsertCopyHandlers(row, { text: insertText, onInsert: () => insertVar(state, ctx, v.path) });
        frag.appendChild(row);
        return;
      }

      if (groupName === "Step IDs") {
        const id = it;
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(id)}</div>
            <div class="wf2cc-sub">Insert existing step id</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;
        WF2CC.ui._attachInsertCopyHandlers(row, { text: id, onInsert: () => insertStepId(state, ctx, id) });
        frag.appendChild(row);
        return;
      }
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  WF2CC.ui.renderGlobalSearch = function renderGlobalSearch(state, ctx) {
    const q = (state.searchEl?.value || "").trim();
    if (!q) return false;

    const presets = Array.isArray(state.catalog.presets) ? state.catalog.presets : [];
    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    const steps = Array.isArray(state.catalog.steps) ? state.catalog.steps : [];

    const templates = globalFilterTemplates(state, ctx, presets).filter((p) =>
      WF2CC.ui._matchesQuery(
        q,
        "template",
        "preset",
        p.title,
        p.description,
        p.id,
        (p.areas || []).join(","),
        (p.triggers || []).join(","),
        (p.step_types || []).join(",")
      )
    );

    const allowedSteps = WF2CC.ui._filterAllowedStepTypes(state, ctx, steps);
    const stepBlocks = allowedSteps.filter((s) =>
      WF2CC.ui._matchesQuery(q, "step", "action", s.type, s.title, s.description, s.category)
    );

    const fields = [];
    allowedSteps.forEach((s) => {
      if (!Array.isArray(s.fields)) return;
      s.fields.forEach((f) => {
        if (WF2CC.ui._matchesQuery(q, "field", "param", "property", s.type, f.title, f.description, f.snippet)) {
          fields.push({ stepType: s.type, field: f });
        }
      });
    });

    const triggers = events.filter((e) => WF2CC.ui._matchesQuery(q, "trigger", "event", e.key, e.description, e.group));
    const vars = getAllVars(state).filter((v) => WF2CC.ui._matchesQuery(q, "var", "vars", "variable", v.path, v.description, v.type));
    const stepIds = (Array.isArray(ctx.stepIds) ? ctx.stepIds : []).filter((id) => WF2CC.ui._matchesQuery(q, "id", "step id", "step", id));

    const grouped = WF2CC.ui._groupify(
      [
        ...templates.map((p) => ({ kind: "Templates", val: p })),
        ...stepBlocks.map((s) => ({ kind: "Steps", val: s })),
        ...fields.map((x) => ({ kind: "Fields", val: x })),
        ...triggers.map((e) => ({ kind: "Triggers", val: e })),
        ...vars.map((v) => ({ kind: "Vars", val: v })),
        ...stepIds.map((id) => ({ kind: "Step IDs", val: id })),
      ],
      (x) => x.kind
    );

    if (!grouped.length) {
      state.groupsEl.innerHTML = "";
      state.listEl.innerHTML = `<div class="wf2cc-empty">No matches.</div>`;
      return true;
    }

    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }

    WF2CC.ui._renderGroups(state, grouped.map((g) => ({ group: g.group, items: g.items })));

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    const items = (current?.items || []).map((x) => x.val);
    renderGlobalGroup(state, ctx, current.group, items);

    return true;
  };
})();