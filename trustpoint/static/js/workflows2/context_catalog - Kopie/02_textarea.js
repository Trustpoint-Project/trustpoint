// static/js/workflows2/context_catalog/02_textarea.js
(function () {
  const WF2CC = window.WF2CC;

  WF2CC.getYamlTextarea = function getYamlTextarea() {
    return document.querySelector("textarea[name='yaml_text']") || document.querySelector("#id_yaml_text");
  };

  function buildLineStarts(lines) {
    const starts = [];
    let pos = 0;
    for (let i = 0; i < lines.length; i += 1) {
      starts.push(pos);
      pos += lines[i].length + 1; // + '\n'
    }
    return starts;
  }

  function getLineStart(text, idx) {
    const i = text.lastIndexOf("\n", idx - 1);
    return i === -1 ? 0 : i + 1;
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

  // IMPORTANT: indent ALL non-empty lines including the first line
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

  // ------- textarea Tab/Shift+Tab indentation -------
  WF2CC.enableTextareaIndent = function enableTextareaIndent(el) {
    if (!el || el._wf2IndentBound) return;
    el._wf2IndentBound = true;

    el.addEventListener("keydown", (e) => {
      if (e.key !== "Tab") return;
      e.preventDefault();

      const indent = WF2CC.config.indent || "  ";
      const value = el.value;
      const start = el.selectionStart ?? 0;
      const end = el.selectionEnd ?? 0;

      // single cursor
      if (start === end) {
        if (e.shiftKey) {
          const ls = getLineStart(value, start);
          const lineEnd = value.indexOf("\n", ls);
          const line = value.slice(ls, lineEnd === -1 ? value.length : lineEnd);
          const cut = line.startsWith(indent) ? indent.length : (line.startsWith(" ") ? 1 : 0);
          if (cut > 0) {
            insertUndoable(el, ls, ls + cut, "");
            el.setSelectionRange(Math.max(ls, start - cut), Math.max(ls, start - cut));
          }
          return;
        }
        insertUndoable(el, start, end, indent);
        el.setSelectionRange(start + indent.length, start + indent.length);
        return;
      }

      // multi-line selection
      const lines = value.split("\n");
      const startLine = value.slice(0, start).split("\n").length - 1;
      const endLine = value.slice(0, end).split("\n").length - 1;

      let deltaStart = 0;
      let deltaEnd = 0;

      for (let ln = startLine; ln <= endLine; ln += 1) {
        const line = lines[ln];
        if (!line.length) continue;

        if (e.shiftKey) {
          if (line.startsWith(indent)) {
            lines[ln] = line.slice(indent.length);
            if (ln === startLine) deltaStart -= indent.length;
            deltaEnd -= indent.length;
          } else if (line.startsWith(" ")) {
            lines[ln] = line.slice(1);
            if (ln === startLine) deltaStart -= 1;
            deltaEnd -= 1;
          }
        } else {
          lines[ln] = indent + line;
          if (ln === startLine) deltaStart += indent.length;
          deltaEnd += indent.length;
        }
      }

      const newValue = lines.join("\n");
      insertUndoable(el, 0, el.value.length, newValue);

      const newStart = Math.max(0, start + deltaStart);
      const newEnd = Math.max(newStart, end + deltaEnd);
      el.setSelectionRange(newStart, newEnd);
    });
  };

  // ------- replace entire line (undoable) -------
  WF2CC.replaceWholeLine = function replaceWholeLine(el, lineNo, newLine) {
    if (!el) return false;
    const lines = el.value.split("\n");
    if (typeof lineNo !== "number" || lineNo < 0 || lineNo >= lines.length) return false;

    const line = lines[lineNo] ?? "";
    const starts = buildLineStarts(lines);
    const startIdx = starts[lineNo];
    const endIdx = startIdx + line.length;

    el.focus();
    insertUndoable(el, startIdx, endIdx, String(newLine));

    const cursor = startIdx + String(newLine).length;
    el.setSelectionRange(cursor, cursor);
    return true;
  };

  // ------- replace scalar value after ":" on a specific line (undoable) -------
  WF2CC.replaceValueAfterColonOnLine = function replaceValueAfterColonOnLine(el, lineNo, newValue) {
    if (!el) return false;

    const lines = el.value.split("\n");
    if (typeof lineNo !== "number" || lineNo < 0 || lineNo >= lines.length) return false;

    const line = lines[lineNo] ?? "";
    if (!line) return false;

    const colon = line.indexOf(":");
    if (colon === -1) return false;

    const afterColon = line.slice(colon + 1);
    const hash = afterColon.indexOf("#");
    const comment = hash !== -1 ? afterColon.slice(hash) : "";
    const keyPart = line.slice(0, colon + 1);

    const next = keyPart + " " + String(newValue) + (comment ? " " + comment.trimStart() : "");

    const starts = buildLineStarts(lines);
    const startIdx = starts[lineNo];
    const endIdx = startIdx + line.length;

    el.focus();
    insertUndoable(el, startIdx, endIdx, next);

    const cursor = startIdx + (keyPart + " " + String(newValue)).length;
    el.setSelectionRange(cursor, cursor);
    return true;
  };

  // ------- core insertion helper (undoable) -------
  WF2CC.insertSmart = function insertSmart(el, snippet, opts) {
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

  // ------- context-aware insertion -------
  WF2CC.smartInsertByContext = function smartInsertByContext(el, snippet, ctx, opts) {
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
    if (anchor === "steps_end") atIndex = lineStartIndex(ctx.anchors.stepsEndLine);
    else if (anchor === "flow_end") atIndex = lineStartIndex(ctx.anchors.flowEndLine);
    else if (anchor === "apply_end") atIndex = lineStartIndex(ctx.anchors.applyEndLine);
    else if (anchor === "trigger_end") atIndex = lineStartIndex(ctx.anchors.triggerEndLine);
    else if (anchor === "sources_end") atIndex = lineStartIndex(ctx.anchors.sourcesEndLine);
    else if (anchor === "workflow_head") atIndex = lineStartIndex(ctx.anchors.workflowHeadLine);
    else if (anchor === "step_end") atIndex = lineStartIndex(ctx.anchors.stepEndLine);
    else if (anchor === "capture_end") atIndex = lineStartIndex(ctx.anchors.captureEndLine);
    else if (anchor === "cases_end") atIndex = lineStartIndex(ctx.anchors.casesEndLine);

    return WF2CC.insertSmart(el, snippet, {
      kind,
      ensureNewline: !!(opts && opts.ensureNewline),
      indentToCursor: !!(opts && opts.indentToCursor),
      baseIndent: (opts && "baseIndent" in opts) ? opts.baseIndent : null,
      atIndex: atIndex !== null ? atIndex : null,
    });
  };

  WF2CC.formatVarInsert = function formatVarInsert(ctx, path) {
    if (ctx.varInsertMode === "expr_inner") return String(path);
    if (ctx.varInsertMode === "vars_target") return "vars.__CURSOR__";
    return "${" + String(path) + "}";
  };
})();
