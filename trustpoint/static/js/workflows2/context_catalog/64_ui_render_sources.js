// static/js/workflows2/context_catalog/64_ui_render_sources.js
(function () {
  const WF2CC = window.WF2CC;

  const SOURCE_KEYS = ["trustpoint", "ca_ids", "domain_ids", "device_ids"];

  function getYamlEl() {
    return WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;
  }

  function linesOf(text) {
    return String(text || "").split(/\r?\n/);
  }

  function isBlankOrComment(line) {
    const t = String(line || "").trim();
    return !t || t.startsWith("#");
  }

  function indentOf(line) {
    const m = String(line || "").match(/^(\s*)/);
    return m ? m[1].length : 0;
  }

  function isKeyLineAtIndent(line, key, indent) {
    const re = new RegExp("^\\s{" + indent + "}" + key + "\\s*:");
    return re.test(String(line || ""));
  }

  function findSourcesBlock(lines) {
    const blocks = WF2CC.yaml.buildBlocks(lines);
    return blocks.sourcesBlock || null;
  }

  function getIndentUnit() {
    const s = (WF2CC.config && WF2CC.config.indent) ? String(WF2CC.config.indent) : "  ";
    return s.replace(/\t/g, "  ").length;
  }

  function getExistingSourceKeys(lines, sourcesBlock) {
    const out = new Set();
    if (!sourcesBlock) return out;

    const indentUnit = getIndentUnit();
    const keyIndent = (sourcesBlock.indent ?? 0) + indentUnit;

    for (let i = sourcesBlock.start + 1; i < sourcesBlock.end; i += 1) {
      const ln = String(lines[i] || "");
      if (isBlankOrComment(ln)) continue;
      if (indentOf(ln) !== keyIndent) continue;

      for (const k of SOURCE_KEYS) {
        if (isKeyLineAtIndent(ln, k, keyIndent)) out.add(k);
      }
    }

    return out;
  }

  // Determine the "active" key under sources by looking at the current line,
  // and if needed scanning upwards inside the sources block.
  function findActiveKey(lines, sourcesBlock, cursorLine) {
    if (!sourcesBlock) return { key: "sources", keyLineNo: sourcesBlock?.start ?? null };

    // If cursor is on the "sources:" line:
    const curLine = String(lines[cursorLine] || "");
    if (/^\s*sources\s*:/.test(curLine.trimStart())) {
      return { key: "sources", keyLineNo: cursorLine };
    }

    const indentUnit = getIndentUnit();
    const keyIndent = (sourcesBlock.indent ?? 0) + indentUnit;

    // If cursor is exactly on a key line:
    if (indentOf(curLine) === keyIndent) {
      for (const k of SOURCE_KEYS) {
        if (isKeyLineAtIndent(curLine, k, keyIndent)) return { key: k, keyLineNo: cursorLine };
      }
    }

    // If cursor is inside list items or blank lines, walk up to find nearest key at keyIndent.
    for (let i = cursorLine; i > sourcesBlock.start; i -= 1) {
      const ln = String(lines[i] || "");
      if (isBlankOrComment(ln)) continue;

      // stop if we escaped sources indentation
      if (indentOf(ln) <= (sourcesBlock.indent ?? 0)) break;

      if (indentOf(ln) === keyIndent) {
        for (const k of SOURCE_KEYS) {
          if (isKeyLineAtIndent(ln, k, keyIndent)) return { key: k, keyLineNo: i };
        }
      }
    }

    // If we couldn't infer a key, show the key picker rather than defaulting to trustpoint.
    return { key: "sources", keyLineNo: sourcesBlock.start };
  }

  function badgeAdded() {
    return `<span style="font-size:.72rem; padding:.1rem .35rem; border-radius:999px; border:1px solid rgba(25,135,84,.35); background:rgba(25,135,84,.10);">Added</span>`;
  }

  function insertSourcesKey(state, ctx, key) {
    const yamlEl = getYamlEl();
    if (!yamlEl) return;

    const line =
      key === "trustpoint" ? "trustpoint: true\n"
      : key === "ca_ids" ? "ca_ids: []\n"
      : key === "domain_ids" ? "domain_ids: []\n"
      : "device_ids: []\n";

    WF2CC.ui._smartInsert(state, ctx, line, {
      kind: "block",
      ensureNewline: false,
      anchor: "sources_end",
      baseIndent: ctx.indents.sourcesEntry, // correct indent under sources:
      indentToCursor: false,
    });
  }

  function renderSourcesKeyPicker(state, ctx, existingKeys) {
    const q = (state.searchEl?.value || "").trim();

    const items = [
      { key: "trustpoint", title: "trustpoint", description: "Match events from anywhere in this Trustpoint (boolean)." },
      { key: "ca_ids", title: "ca_ids", description: "Restrict trigger to specific Issuing CA ids." },
      { key: "domain_ids", title: "domain_ids", description: "Restrict trigger to specific Domain ids." },
      { key: "device_ids", title: "device_ids", description: "Restrict trigger to specific Device ids (strings)." },
    ].filter((it) => WF2CC.ui._matchesQuery(q, it.title, it.description));

    const grouped = [{ group: "Sources", items, __kind: "sources_keys" }];
    state.selectedGroup = "Sources";
    WF2CC.ui._renderGroups(state, grouped);

    const frag = document.createDocumentFragment();
    items.forEach((it) => {
      const already = existingKeys.has(it.key);

      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600; display:flex; align-items:center; gap:.5rem;">
            ${WF2CC.esc(it.title)}
            ${already ? badgeAdded() : ""}
          </div>
          <div class="wf2cc-sub">${WF2CC.esc(it.description || "")}</div>
        </div>
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: it.key,
        onInsert: already ? null : () => insertSourcesKey(state, ctx, it.key),
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function renderTrustpointBool(state, ctx, keyLineNo) {
    const yamlEl = getYamlEl();
    const q = (state.searchEl?.value || "").trim().toLowerCase();

    const choices = [
      { label: "true", value: "true", description: "Enable this source filter." },
      { label: "false", value: "false", description: "Disable this source filter." },
    ].filter((x) => !q || (x.label + " " + x.description).toLowerCase().includes(q));

    const grouped = [{ group: "Trustpoint", items: choices }];
    state.selectedGroup = "Trustpoint";
    WF2CC.ui._renderGroups(state, grouped);

    const frag = document.createDocumentFragment();
    choices.forEach((it) => {
      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(it.label)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(it.description)}</div>
        </div>
        ${WF2CC.ui._itemButtons()}
      `;
      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: it.value,
        onInsert: () => {
          if (!yamlEl) return;
          WF2CC.replaceValueAfterColonOnLine(yamlEl, keyLineNo, it.value);
        },
      });
      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  function findListInsertIndex(lines, keyLineNo, keyIndent) {
    // Insert before the first line that returns to keyIndent or less (end of this key’s block).
    for (let i = keyLineNo + 1; i < lines.length; i += 1) {
      const ln = String(lines[i] || "");
      if (isBlankOrComment(ln)) continue;
      const ind = indentOf(ln);
      if (ind <= keyIndent) return i;
    }
    return lines.length;
  }

  function renderIdList(state, ctx, title, keyName, keyLineNo, items, valueField) {
    const yamlEl = getYamlEl();
    if (!yamlEl) return;

    const q = (state.searchEl?.value || "").trim();
    const vals = Array.isArray(items) ? items : [];
    const filtered = vals.filter((it) =>
      WF2CC.ui._matchesQuery(q, it.name || it.title || it.label || "", String(it[valueField] ?? it.id ?? ""), it.description || "")
    );

    const grouped = [{ group: title, items: filtered }];
    state.selectedGroup = title;
    WF2CC.ui._renderGroups(state, grouped);

    // If key doesn't exist yet, show a single action row to add the key first.
    if (keyLineNo == null) {
      state.listEl.innerHTML = `
        <div class="wf2cc-empty">
          <div style="margin-bottom:.5rem;">Key <code>${WF2CC.esc(keyName)}</code> is not present yet.</div>
          <button type="button" class="btn btn-sm btn-primary" id="wf2cc-add-key">Add ${WF2CC.esc(keyName)}</button>
        </div>
      `;
      const btn = state.listEl.querySelector("#wf2cc-add-key");
      if (btn) btn.addEventListener("click", () => insertSourcesKey(state, ctx, keyName));
      return;
    }

    const lines = linesOf(yamlEl.value);
    const sourcesBlock = findSourcesBlock(lines);
    const indentUnit = getIndentUnit();
    const keyIndent = (sourcesBlock?.indent ?? 0) + indentUnit;
    const listItemIndent = keyIndent + indentUnit;

    const insertAtLine = findListInsertIndex(lines, keyLineNo, keyIndent);
    const insertAtIdx = (() => {
      // map line -> char index
      let idx = 0;
      for (let i = 0; i < insertAtLine; i += 1) idx += lines[i].length + 1;
      return idx;
    })();

    const frag = document.createDocumentFragment();

    if (!filtered.length) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No matches.</div>`;
      return;
    }

    filtered.forEach((it) => {
      const idVal = it[valueField] ?? it.id;
      const label = it.name || it.title || it.label || String(idVal);

      const row = document.createElement("div");
      row.className = "wf2cc-item";
      row.innerHTML = `
        <div style="min-width:0;">
          <div style="font-weight:600;">${WF2CC.esc(label)}</div>
          <div class="wf2cc-sub">${WF2CC.esc(String(idVal))}</div>
        </div>
        ${WF2CC.ui._itemButtons()}
      `;

      WF2CC.ui._attachInsertCopyHandlers(row, {
        text: String(idVal),
        onInsert: () => {
          // Insert list item at the end of the specific list, with correct indentation.
          WF2CC.insertSmart(yamlEl, `- ${String(idVal)}\n`, {
            kind: "block",
            ensureNewline: true,
            atIndex: insertAtIdx,
            baseIndent: listItemIndent,
            indentToCursor: false,
          });
        },
      });

      frag.appendChild(row);
    });

    state.listEl.innerHTML = "";
    state.listEl.appendChild(frag);
  }

  WF2CC.ui.renderSources = function renderSources(state, ctx) {
    const yamlEl = getYamlEl();
    if (!yamlEl) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No editor found.</div>`;
      return;
    }

    const lines = linesOf(yamlEl.value);
    const sourcesBlock = findSourcesBlock(lines);
    if (!sourcesBlock) {
      state.listEl.innerHTML = `<div class="wf2cc-empty">No <code>trigger.sources</code> block found.</div>`;
      return;
    }

    const existingKeys = getExistingSourceKeys(lines, sourcesBlock);
    const active = findActiveKey(lines, sourcesBlock, Number(ctx.lineNo ?? 0));

    // sources: line / unknown position => offer keys picker
    if (active.key === "sources") {
      return renderSourcesKeyPicker(state, ctx, existingKeys);
    }

    // Trustpoint boolean
    if (active.key === "trustpoint") {
      return renderTrustpointBool(state, ctx, active.keyLineNo);
    }

    if (active.key === "ca_ids") {
      return renderIdList(state, ctx, "CAs", "ca_ids", active.keyLineNo, state.sources && state.sources.cas, "id");
    }
    if (active.key === "domain_ids") {
      return renderIdList(state, ctx, "Domains", "domain_ids", active.keyLineNo, state.sources && state.sources.domains, "id");
    }
    if (active.key === "device_ids") {
      return renderIdList(state, ctx, "Devices", "device_ids", active.keyLineNo, state.sources && state.sources.devices, "id");
    }

    return renderSourcesKeyPicker(state, ctx, existingKeys);
  };
})();