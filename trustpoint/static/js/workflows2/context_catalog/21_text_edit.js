// static/js/workflows2/context_catalog/21_text_edit.js
(function () {
  const WF2CC = window.WF2CC;

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

  function getLineEnd(text, idx) {
    const i = text.indexOf("\n", idx);
    return i === -1 ? text.length : i;
  }

  function getLineIndentString(line) {
    const m = String(line || "").match(/^(\s*)/);
    return m ? m[1] : "";
  }

  function insertUndoable(el, start, end, text) {
    el.setRangeText(text, start, end, "end");
    el.dispatchEvent(new Event("input", { bubbles: true }));
    // best-effort focus restore (don’t fight the browser too hard)
    setTimeout(() => {
      try { el.focus(); } catch { /* ignore */ }
    }, 0);
  }

  // Determine indent to insert on Enter.
  // Rules:
  // - new line keeps current line indent
  // - if current line (up to cursor) ends with ":" -> add one indent unit
  // - if current line is a bare list item "-"/"- " -> add one indent unit
  function computeEnterIndent(value, cursorPos) {
    const indentUnit = (WF2CC.config && WF2CC.config.indent) ? String(WF2CC.config.indent) : "  ";

    const ls = getLineStart(value, cursorPos);
    const le = getLineEnd(value, cursorPos);
    const line = value.slice(ls, le);
    const beforeCursorOnLine = value.slice(ls, cursorPos);

    const baseIndent = getLineIndentString(line);
    const trimmedBefore = String(beforeCursorOnLine).replace(/\s+$/, "");

    // YAML mapping opener: "key:"
    const endsWithColon = trimmedBefore.endsWith(":");
    // Bare list item: "-" or "- "
    const isBareDash = /^\s*-\s*$/.test(trimmedBefore);

    if (endsWithColon || isBareDash) return baseIndent + indentUnit;
    return baseIndent;
  }

  // ------- textarea Tab/Shift+Tab indentation + Enter auto-indent -------
  WF2CC.edit = WF2CC.edit || {};

  WF2CC.edit.enableTextareaIndent = function enableTextareaIndent(el) {
    if (!el || el._wf2IndentBound) return;
    el._wf2IndentBound = true;

    el.addEventListener("keydown", (e) => {
      const indent = (WF2CC.config && WF2CC.config.indent) ? String(WF2CC.config.indent) : "  ";

      // ✅ Enter auto-indent
      if (e.key === "Enter") {
        if (e.isComposing) return; // don’t interfere with IME
        e.preventDefault();

        const value = el.value;
        const start = el.selectionStart ?? 0;
        const end = el.selectionEnd ?? 0;

        const insIndent = computeEnterIndent(value, start);
        const toInsert = "\n" + insIndent;

        insertUndoable(el, start, end, toInsert);

        const newPos = start + toInsert.length;
        el.setSelectionRange(newPos, newPos);
        return;
      }

      // ✅ Tab / Shift+Tab indentation
      if (e.key !== "Tab") return;
      e.preventDefault();

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

      // If selection ends exactly at the start of a line, don't treat that line as selected
      let endLine = value.slice(0, end).split("\n").length - 1;
      if (end > start && value[end - 1] === "\n") endLine -= 1;
      if (endLine < startLine) endLine = startLine;

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

  // Backwards-compatible alias
  WF2CC.enableTextareaIndent = WF2CC.edit.enableTextareaIndent;

  // ------- replace entire line (undoable) -------
  WF2CC.edit.replaceWholeLine = function replaceWholeLine(el, lineNo, newLine) {
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
  WF2CC.replaceWholeLine = WF2CC.edit.replaceWholeLine;

  // ------- replace scalar value after ":" on a specific line (undoable) -------
  WF2CC.edit.replaceValueAfterColonOnLine = function replaceValueAfterColonOnLine(el, lineNo, newValue) {
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
  WF2CC.replaceValueAfterColonOnLine = WF2CC.edit.replaceValueAfterColonOnLine;
})();