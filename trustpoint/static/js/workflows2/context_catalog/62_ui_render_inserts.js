// static/js/workflows2/context_catalog/62_ui_render_inserts.js
(function () {
  const WF2CC = window.WF2CC;

  function isValueOnlySnippet(f) {
    const sn = String((f && f.snippet) || "");
    if (!sn) return false;
    if (sn.includes("\n")) return false;
    if (sn.includes(":")) return false;
    return true;
  }

  function inferFieldKey(stepType, f) {
    if (f && f.key) return String(f.key);
    if (f && f.id) return String(f.id);

    const t = String((f && f.title) || "");
    if (t.includes(".")) return t.split(".").pop().trim();
    if (t.includes("·")) return t.split("·").pop().trim().toLowerCase().replace(/\s+/g, "_");
    return t.trim().toLowerCase().replace(/\s+/g, "_");
  }

  function makeKeyLine(key, valueSnippet) {
    const v = String(valueSnippet || "").trim();
    const looksScalar =
      /^["'].*["']$/.test(v) ||
      /^[0-9]+(\.[0-9]+)?$/.test(v) ||
      /^(true|false|null)$/i.test(v);
    const val = looksScalar ? v : `"${v}"`;
    return `${key}: ${val}`;
  }

  function badgeRequired() {
    return `<span style="font-size:.72rem; padding:.1rem .35rem; border-radius:999px; border:1px solid rgba(13,110,253,.35); background:rgba(13,110,253,.10);">Required</span>`;
  }

  function badgeOptional() {
    return `<span style="font-size:.72rem; padding:.1rem .35rem; border-radius:999px; border:1px solid rgba(0,0,0,.12); background:rgba(0,0,0,.03);">Optional</span>`;
  }

  function badgeAdded() {
    return `<span style="font-size:.72rem; padding:.1rem .35rem; border-radius:999px; border:1px solid rgba(25,135,84,.35); background:rgba(25,135,84,.10);">Added</span>`;
  }

  function isRequiredField(f) {
    return !!(f && f.required);
  }

  function filterFieldsByMode(state, fields) {
    const mode = String(state.mode || "mandatory");
    if (mode === "optional") return fields;
    return fields.filter(isRequiredField);
  }

  function renderInsertTriggers(state, ctx) {
    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    const q = (state.searchEl.value || "").trim();
    const filtered = events.filter((e) =>
      WF2CC.ui._matchesQuery(q, "trigger", "event", e.key, e.description, e.group)
    );

    const grouped = WF2CC.ui._groupify(filtered, (e) => e.group || "Other");
    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }
    WF2CC.ui._renderGroups(state, grouped);

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
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: e.key,
        onInsert: () => {
          const yamlEl = WF2CC.getYamlTextarea();
          if (!yamlEl) return;
          if (ctx.area === "trigger.on") WF2CC.ui._replaceOnCurrentLine(state, ctx, e.key);
          else WF2CC.insertSmart(yamlEl, e.key, { kind: "inline" });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function renderInsertTemplates(state, ctx, areasHint) {
    const presets = Array.isArray(state.catalog.presets) ? state.catalog.presets : [];
    const q = (state.searchEl.value || "").trim();

    const filtered = WF2CC.ui._filterTemplates(state, ctx, presets)
      .filter((p) => WF2CC.ui._matchesQuery(q, p.title, p.description, p.id));

    const grouped = WF2CC.ui._groupify(filtered, (p) => ((p.areas && p.areas[0]) || "misc"));

    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }
    WF2CC.ui._preferGroup(state, grouped, areasHint);

    WF2CC.ui._renderGroups(state, grouped);

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
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: p.snippet,
        onInsert: () => {
          const yamlEl = WF2CC.getYamlTextarea();
          if (!yamlEl) return;

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
            indentToCursor: false,
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

    const items = ids.filter((id) => WF2CC.ui._matchesQuery(q, id)).map((id) => ({ group: "Step IDs", id }));
    const grouped = WF2CC.ui._groupify(items, (x) => x.group);

    state.selectedGroup = "Step IDs";
    WF2CC.ui._renderGroups(state, grouped);

    const frag = document.createDocumentFragment();
    items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(it.id)}</div>
          <div class="wf2cc-sub">Insert existing step id</div>
        </div>
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: it.id,
        onInsert: () => WF2CC.ui._replaceOnCurrentLine(state, ctx, it.id),
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function filterPickerValuesByQuery(q, picker) {
    if (!picker || !Array.isArray(picker.values)) return null;
    const qq = String(q || "").trim().toLowerCase();
    if (!qq) return picker;

    const vals = picker.values.filter((v) => {
      const hay = `${v.label || ""} ${v.value || ""} ${v.snippet || ""} ${v.description || ""}`.toLowerCase();
      return hay.includes(qq);
    });

    return { ...picker, values: vals };
  }

  function renderInsertSteps(state, ctx) {
    const steps = Array.isArray(state.catalog.steps) ? state.catalog.steps : [];
    const q = (state.searchEl.value || "").trim();

    const allowed = WF2CC.ui._filterAllowedStepTypes(state, ctx, steps);

    // Step block list (only relevant when not already in a step)
    const filteredBlocks = allowed.filter((s) =>
      WF2CC.ui._matchesQuery(q, "step", "action", s.type, s.title, s.description, s.category)
    );
    const stepGroups = WF2CC.ui._groupify(filteredBlocks, (s) => (s.category === "terminal" ? "Terminal" : "Steps"));

    const currentStepDef = ctx.stepType
      ? allowed.find((s) => String(s.type) === String(ctx.stepType)) || null
      : null;

    const allFields = (currentStepDef && Array.isArray(currentStepDef.fields)) ? currentStepDef.fields : [];
    const stepTypeName = ctx.stepType ? String(ctx.stepType) : null;

    // show only mandatory fields unless mode=optional
    const fieldsByMode = filterFieldsByMode(state, allFields);

    // Detect existing keys (so we can disable instead of hiding)
    let existingKeys = new Set();
    try {
      const yamlEl = WF2CC.getYamlTextarea();
      if (yamlEl && WF2CC.yaml.getCurrentStepRootKeys) {
        existingKeys = WF2CC.yaml.getCurrentStepRootKeys(yamlEl.value, ctx);
      }
    } catch { /* ignore */ }

    // Build picker (operators/values/etc) ALWAYS, but filter by search.
    let picker = null;
    if (WF2CC.pickers && typeof WF2CC.pickers.getPicker === "function") {
      picker = filterPickerValuesByQuery(q, WF2CC.pickers.getPicker(ctx));
      if (picker && Array.isArray(picker.values) && picker.values.length === 0) picker = null;
    }

    const grouped = [...stepGroups];

    // Fields group (always shown if in a step type)
    if (stepTypeName && fieldsByMode.length) {
      grouped.unshift({ group: stepTypeName, items: fieldsByMode, __kind: "fields" });
      if (!state.manualGroup) state.selectedGroup = stepTypeName;
    }

    // Picker group on top
    if (picker && Array.isArray(picker.values) && picker.values.length) {
      const gname = picker.groupTitle || "Values";
      grouped.unshift({ group: gname, items: picker.values, __kind: "picker", __picker: picker });
      if (!state.manualGroup) state.selectedGroup = gname;
    }

    if (!state.selectedGroup || !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }

    WF2CC.ui._renderGroups(state, grouped);

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    if (!current || !current.items || !current.items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No matches.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();

    // Picker rendering
    if (current.__kind === "picker") {
      const yamlEl = WF2CC.getYamlTextarea();
      const pickerAction = (current.__picker && current.__picker.action) ? String(current.__picker.action) : "replace_value";

      current.items.forEach((it) => {
        const label = it && it.label ? String(it.label) : "";
        const desc = it && it.description ? String(it.description) : "";

        const copyText =
          pickerAction === "insert_snippet"
            ? String(it && it.snippet ? it.snippet : "")
            : String(it && it.value ? it.value : "");

        const valueLine =
          pickerAction === "insert_snippet"
            ? (it && it.snippet ? String(it.snippet).trimEnd() : "")
            : (it && it.value ? String(it.value) : "");

        const row = document.createElement("div");
        row.className = "wf2cc-item";
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600;">${WF2CC.esc(label || valueLine)}</div>
            <div class="wf2cc-sub">${WF2CC.esc(valueLine)}</div>
            ${desc ? `<div style="font-size:.85rem; opacity:.85; margin-top:.15rem;">${WF2CC.esc(desc)}</div>` : ""}
          </div>
          ${WF2CC.ui._itemButtons()}
        `;

        WF2CC.ui._attachInsertCopyHandlers(row, {
          text: copyText,
          onInsert: () => {
            if (!yamlEl) return;

            if (pickerAction === "replace_value") {
              if (typeof ctx.lineNo !== "number") return;
              const v = String(it && it.value ? it.value : "");
              if (!v) return;
              WF2CC.replaceValueAfterColonOnLine(yamlEl, ctx.lineNo, v);
              return;
            }

            if (pickerAction === "insert_snippet") {
              const sn = String(it && it.snippet ? it.snippet : "");
              if (!sn) return;

              // Insert snippets should respect correct base indentation in the current area.
              let anchor = "cursor_line_next";
              let baseIndent = null;

              if (String(ctx.area || "") === "workflow.steps.webhook.capture") {
                anchor = "capture_end";
                baseIndent = ctx.indents.captureEntry;
              } else if (String(ctx.area || "") === "workflow.steps.logic.cases") {
                anchor = "cases_end";
                baseIndent = ctx.indents.casesItem;
              } else if (String(ctx.area || "").startsWith("workflow.steps")) {
                baseIndent = ctx.indents.stepField;
              }

              WF2CC.ui._smartInsert(state, ctx, sn, {
                kind: "block",
                ensureNewline: false,
                anchor,
                baseIndent,
                indentToCursor: false,
              });
            }
          },
        });

        frag.appendChild(row);
      });

      state.listEl.innerHTML = "";
      state.listEl.appendChild(frag);
      return;
    }

    // Fields rendering (uniform: show Added instead of hiding)
    if (stepTypeName && current.group === stepTypeName) {
      current.items.forEach((f) => {
        const key = inferFieldKey(stepTypeName, f);
        const added = existingKeys.has(key);

        const snippet = isValueOnlySnippet(f) ? makeKeyLine(key, f.snippet) : String(f.snippet || "");

        const badge = added
          ? badgeAdded()
          : (isRequiredField(f) ? badgeRequired() : badgeOptional());

        const row = document.createElement("div");
        row.className = "wf2cc-item";
        row.innerHTML = `
          <div style="min-width:0;">
            <div style="font-weight:600; display:flex; align-items:center; gap:.5rem;">
              <span>${WF2CC.esc(f.title || (stepTypeName + "." + key))}</span>
              ${badge}
            </div>
            <div class="wf2cc-sub">${WF2CC.esc(f.description || "")}</div>
          </div>
          ${WF2CC.ui._itemButtons()}
        `;

        WF2CC.ui._attachInsertCopyHandlers(row, {
          text: snippet,
          onInsert: added ? null : () => {
            // Root-level fields always belong at stepField indentation.
            let anchor = "cursor_line_next";
            let baseIndent = ctx.indents.stepField;

            if (String(ctx.area || "") === "workflow.steps.webhook.capture") {
              anchor = "capture_end";
              baseIndent = ctx.indents.captureEntry;
            } else if (String(ctx.area || "") === "workflow.steps.logic.cases") {
              anchor = "cases_end";
              baseIndent = ctx.indents.casesItem;
            }

            WF2CC.ui._smartInsert(state, ctx, snippet, {
              kind: "block",
              ensureNewline: false,
              anchor,
              baseIndent,
              indentToCursor: false,
            });
          },
        });

        frag.appendChild(row);
      });

      state.listEl.innerHTML = "";
      state.listEl.appendChild(frag);
      return;
    }

    // Step blocks list
    current.items.forEach((s) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(s.title || s.type)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(s.type)} · ${WF2CC.esc(s.description || "")}</div>
        </div>
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: s.block_snippet,
        onInsert: () => {
          WF2CC.ui._smartInsert(state, ctx, s.block_snippet, {
            kind: "block",
            ensureNewline: false,
            anchor: "steps_end",
            baseIndent: ctx.indents.stepItem,
            indentToCursor: false,
          });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  WF2CC.ui.renderInsert = function renderInsert(state, ctx) {
    if (ctx.area && ctx.area.startsWith("trigger.sources") && WF2CC.ui.renderSources) {
      return WF2CC.ui.renderSources(state, ctx);
    }

    const q = (state.searchEl?.value || "").trim();
    if (q && typeof WF2CC.ui.renderGlobalSearch === "function") {
      const didRender = WF2CC.ui.renderGlobalSearch(state, ctx);
      if (didRender) return;
    }

    if (ctx.area === "trigger.on") return renderInsertTriggers(state, ctx);
    if (ctx.area === "trigger.sources") return renderInsertTemplates(state, ctx, "trigger.sources");
    if (ctx.area.startsWith("trigger")) return renderInsertTemplates(state, ctx, "trigger");

    if (ctx.area === "apply") return renderInsertTemplates(state, ctx, "apply");

    if (ctx.area === "workflow.start") return renderInsertStepIdPicker(state, ctx);
    if (ctx.area === "workflow.flow.from" || ctx.area === "workflow.flow.to") return renderInsertStepIdPicker(state, ctx);
    if (ctx.area.startsWith("workflow.flow")) return renderInsertTemplates(state, ctx, "workflow.flow");

    if (ctx.area.startsWith("workflow.steps")) return renderInsertSteps(state, ctx);

    return renderInsertTemplates(state, ctx, "root");
  };
})();