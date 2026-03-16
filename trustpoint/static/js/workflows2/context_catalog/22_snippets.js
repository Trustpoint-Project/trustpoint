// static/js/workflows2/context_catalog/22_snippets.js
(function () {
  const WF2CC = window.WF2CC;

  function getLineStart(text, idx) {
    const i = text.lastIndexOf("\n", idx - 1);
    return i === -1 ? 0 : i + 1;
  }

  function getLineEnd(text, idx) {
    const i = text.indexOf("\n", idx);
    return i === -1 ? text.length : i;
  }

  function getLineIndent(text, idx) {
    const ls = getLineStart(text, idx);
    const m = text.slice(ls).match(/^(\s*)/);
    return m ? m[1] : "";
  }

  function indentStr(n) {
    const nn = Math.max(0, Number(n || 0));
    return " ".repeat(nn);
  }

  function normalizeBaseIndent(x) {
    if (x === null || x === undefined) return null;
    if (typeof x === "number") return indentStr(x);
    if (typeof x === "string" && /^\d+$/.test(x.trim())) return indentStr(parseInt(x.trim(), 10));
    return String(x);
  }

  function findFirstPlaceholder(snippet) {
    const idxCursor = snippet.indexOf("__CURSOR__");
    if (idxCursor !== -1) return { token: "__CURSOR__", index: idxCursor, len: "__CURSOR__".length };
    const m = snippet.match(/__([A-Za-z0-9_]+)__/);
    if (!m) return null;
    return { token: m[0], index: m.index, len: m[0].length };
  }

  function stripToken(snippet, token) {
    return snippet.split(token).join("");
  }

  // indent ALL non-empty lines including the first line
  function indentBlock(snippet, baseIndent) {
    const lines = String(snippet || "").split("\n");
    return lines.map((ln) => (ln.length ? baseIndent + ln : ln)).join("\n");
  }

  function insertUndoable(el, start, end, text) {
    el.setRangeText(text, start, end, "end");
    el.dispatchEvent(new Event("input", { bubbles: true }));
    setTimeout(() => {
      try { el.focus(); } catch { /* ignore */ }
    }, 0);
  }

  // ------- core insertion helper (undoable) -------
  WF2CC.snippets.insertSmart = function insertSmart(el, snippet, opts) {
    if (!el) return false;
    el.focus();

    const kind = (opts && opts.kind) || "inline"; // "inline" | "block"
    const ensureNewline = !!(opts && opts.ensureNewline);
    const indentToCursor = !!(opts && opts.indentToCursor);
    const baseIndentOverrideRaw = (opts && opts.baseIndent) || null;
    const baseIndentOverride = normalizeBaseIndent(baseIndentOverrideRaw);
    const atIndex = (opts && typeof opts.atIndex === "number") ? opts.atIndex : null;

    let start = el.selectionStart ?? 0;
    let end = el.selectionEnd ?? 0;
    if (atIndex !== null) start = end = atIndex;

    let insert = String(snippet);

    const baseIndent = baseIndentOverride !== null
      ? baseIndentOverride
      : (indentToCursor ? getLineIndent(el.value, start) : "");

    if (kind === "block") {
      insert = indentBlock(insert, baseIndent);

      const before = el.value.slice(0, start);
      const prevChar = before.length ? before[before.length - 1] : "";
      const needNL = ensureNewline || (prevChar && prevChar !== "\n");

      if (needNL && !insert.startsWith("\n")) insert = "\n" + insert;
      if (!insert.endsWith("\n")) insert = insert + "\n";
    }

    const ph = findFirstPlaceholder(insert);
    const insertWithoutToken = ph ? stripToken(insert, ph.token) : insert;

    insertUndoable(el, start, end, insertWithoutToken);

    if (ph) {
      const cursorPos = start + ph.index;
      el.setSelectionRange(cursorPos, cursorPos);
    }
    return true;
  };

  WF2CC.insertSmart = WF2CC.snippets.insertSmart;

  function buildLineStarts(lines) {
    const starts = [];
    let pos = 0;
    for (let i = 0; i < lines.length; i += 1) {
      starts.push(pos);
      pos += lines[i].length + 1;
    }
    return starts;
  }

  function clampIndex(maxLen, idx) {
    const i = Number(idx || 0);
    if (i < 0) return 0;
    if (i > maxLen) return maxLen;
    return i;
  }

  // ------- context-aware insertion -------
  WF2CC.snippets.smartInsertByContext = function smartInsertByContext(el, snippet, ctx, opts) {
    if (!el) return false;

    const anchor = (opts && opts.anchor) || "cursor";
    const kind = (opts && opts.kind) || "inline";

    const lines = el.value.split("\n");
    const starts = buildLineStarts(lines);

    function lineStartIndex(ln) {
      if (ln === null || ln === undefined) return null;
      if (ln < 0) return 0;
      if (ln >= starts.length) return el.value.length;
      return starts[ln];
    }

    let atIndex = null;

    // ✅ FIX: cursor_line_next should insert at the START of the next line, not BEFORE the newline.
    // Otherwise block insert adds its own "\n" and you end up with extra blank lines / wrong nesting.
    if (anchor === "cursor_line_next") {
      const pos = el.selectionStart ?? 0;
      const eol = getLineEnd(el.value, pos);          // points at "\n" or end-of-text
      const hasNl = el.value[eol] === "\n";
      atIndex = clampIndex(el.value.length, hasNl ? (eol + 1) : eol);
    } else if (anchor === "steps_end") atIndex = lineStartIndex(ctx.anchors.stepsEndLine);
    else if (anchor === "flow_end") atIndex = lineStartIndex(ctx.anchors.flowEndLine);
    else if (anchor === "apply_end") atIndex = lineStartIndex(ctx.anchors.applyEndLine);
    else if (anchor === "trigger_end") atIndex = lineStartIndex(ctx.anchors.triggerEndLine);
    else if (anchor === "sources_end") atIndex = lineStartIndex(ctx.anchors.sourcesEndLine);
    else if (anchor === "workflow_head") atIndex = lineStartIndex(ctx.anchors.workflowHeadLine);
    else if (anchor === "step_end") atIndex = lineStartIndex(ctx.anchors.stepEndLine);
    else if (anchor === "capture_end") atIndex = lineStartIndex(ctx.anchors.captureEndLine);
    else if (anchor === "cases_end") atIndex = lineStartIndex(ctx.anchors.casesEndLine);

    return WF2CC.snippets.insertSmart(el, snippet, {
      kind,
      ensureNewline: !!(opts && opts.ensureNewline),
      indentToCursor: !!(opts && opts.indentToCursor),
      baseIndent: (opts && "baseIndent" in opts) ? opts.baseIndent : null,
      atIndex: atIndex !== null ? atIndex : null,
    });
  };

  WF2CC.smartInsertByContext = WF2CC.snippets.smartInsertByContext;

  WF2CC.snippets.formatVarInsert = function formatVarInsert(ctx, path) {
    if (ctx.varInsertMode === "expr_inner") return String(path);
    if (ctx.varInsertMode === "vars_target") return "vars.__CURSOR__";
    return "${" + String(path) + "}";
  };

  WF2CC.formatVarInsert = WF2CC.snippets.formatVarInsert;
})();