// static/js/workflows2/context_catalog/61_ui_render_vars.js
(function () {
  const WF2CC = window.WF2CC;

  function shouldFilterByTrigger(ctx) {
    return WF2CC.ui._shouldFilterByTrigger ? WF2CC.ui._shouldFilterByTrigger(ctx) : !!ctx.triggerOn;
  }

  function formatPath(ctx, path) {
    return WF2CC.formatVarInsert ? WF2CC.formatVarInsert(ctx, path) : ("${" + path + "}");
  }

  function getTriggerVarItems(state, ctx) {
    const events = Array.isArray(state.catalog.events) ? state.catalog.events : [];
    const candidates = (shouldFilterByTrigger(ctx) && ctx.triggerOn)
      ? events.filter((e) => String(e.key) === String(ctx.triggerOn))
      : events;

    const map = new Map();
    candidates.forEach((e) => {
      (e.context_vars || []).forEach((v) => {
        if (!v || !v.path) return;
        if (!map.has(v.path)) map.set(v.path, v);
      });
    });

    return [...map.values()].map((v) => ({
      group: "Trigger vars",
      label: v.description || v.path,
      path: v.path,
      insert: formatPath(ctx, v.path),
      description: v.description || "",
    }));
  }

  // Collect vars produced by the YAML itself:
  // - webhook capture targets:   status_code: vars.http_status
  // - compute set targets:       vars.score:
  // - set step vars keys:        vars: { final: ... } -> vars.final
  function getProducedVars(ctx) {
    const yamlEl = WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;
    if (!yamlEl) return [];

    const lines = String(yamlEl.value || "").split(/\r?\n/);
    const out = new Map(); // path -> {path, hint}

    // 1) capture targets
    for (const ln of lines) {
      const m = String(ln || "").match(/^\s*(status_code|body|headers)\s*:\s*(vars\.[A-Za-z0-9_.-]+)\s*$/);
      if (m) {
        const p = m[2];
        if (!out.has(p)) out.set(p, { path: p, hint: `Captured ${m[1]}` });
      }
    }

    // 2) compute set targets (keys are vars.<name>:)
    for (const ln of lines) {
      const m = String(ln || "").match(/^\s*(vars\.[A-Za-z0-9_.-]+)\s*:\s*/);
      if (m) {
        const p = m[1];
        if (!out.has(p)) out.set(p, { path: p, hint: "Computed var" });
      }
    }

    // 3) set step vars keys: find "vars:" blocks and read direct child keys
    for (let i = 0; i < lines.length; i += 1) {
      const ln = String(lines[i] || "");
      const mVars = ln.match(/^(\s*)vars\s*:\s*(.*)$/);
      if (!mVars) continue;

      const baseIndent = mVars[1].length;
      const childIndentMin = baseIndent + 2;

      // scan downward until indent <= baseIndent
      for (let j = i + 1; j < lines.length; j += 1) {
        const l2 = String(lines[j] || "");
        if (!l2.trim()) continue;

        const ind = (l2.match(/^(\s*)/) || ["", ""])[1].length;
        if (ind <= baseIndent) break;
        if (ind < childIndentMin) continue;

        const t = l2.trimStart();
        if (t.startsWith("-")) continue;

        const mk = t.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:/);
        if (!mk) continue;

        const key = mk[1];
        if (!key) continue;

        const p = "vars." + key;
        if (!out.has(p)) out.set(p, { path: p, hint: "Set var" });
      }
    }

    return [...out.values()].map((x) => ({
      group: "Workflow vars",
      label: x.path,
      path: x.path,
      insert: formatPath(ctx, x.path),
      description: x.hint || "",
    }));
  }

  WF2CC.ui.renderVars = function renderVars(state, ctx) {
    const q = (state.searchEl?.value || "").trim();

    const triggerItems = getTriggerVarItems(state, ctx);
    const producedVars = getProducedVars(ctx);

    // Combine + filter
    const all = [...triggerItems, ...producedVars].filter((it) =>
      WF2CC.ui._matchesQuery(q, it.label, it.insert, it.group, it.description)
    );

    const grouped = WF2CC.ui._groupify(all, (it) => it.group || "Other");
    if (!state.selectedGroup) state.selectedGroup = grouped[0]?.group || null;
    if (state.selectedGroup && !grouped.some((g) => g.group === state.selectedGroup)) {
      state.selectedGroup = grouped[0]?.group || null;
    }

    WF2CC.ui._renderGroups(state, grouped);

    const current = grouped.find((g) => g.group === state.selectedGroup) || grouped[0];
    if (!current || !current.items.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No matches.</div>`;
      return;
    }

    const frag = document.createDocumentFragment();
    current.items.forEach((it) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(it.label)}</div>
          <div class="wf2cc-sub"><code>${WF2CC.esc(it.insert)}</code></div>
          ${it.description ? `<div style="font-size:.85rem; opacity:.85; margin-top:.15rem;">${WF2CC.esc(it.description)}</div>` : ""}
        </div>
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: it.insert,
        onInsert: () => {
          // insertSmart already refuses inputs and falls back to YAML textarea
          WF2CC.insertSmart(state.getInsertTarget(), it.insert, { kind: "inline" });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  };
})();