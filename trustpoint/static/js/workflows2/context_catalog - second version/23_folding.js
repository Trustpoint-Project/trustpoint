// static/js/workflows2/context_catalog/23_folding.js
(function () {
  const WF2CC = window.WF2CC;
  if (!WF2CC) return;

  WF2CC.folding = WF2CC.folding || {};

  const MARKER_VISIBLE = "# \u2026"; // "# …"

  // Zero-width payload encoding (should not render)
  const Z0 = "\u200B"; // ZERO WIDTH SPACE
  const Z1 = "\u200C"; // ZERO WIDTH NON-JOINER
  const PFX = Z0 + Z0 + Z0 + Z0; // prefix (4x ZWSP)

  // Legacy support (old markers)
  const LEGACY_INV = "\u2063";

  const foldStore = new Map();
  let seq = 0;

  function makeIdHex8() {
    seq += 1;
    return seq.toString(16).padStart(8, "0");
  }

  function encodeId(hex8) {
    // 8 hex chars => 32 bits => 32 ZW chars
    let out = PFX;
    for (const ch of String(hex8)) {
      const n = parseInt(ch, 16);
      out += (n & 8) ? Z1 : Z0;
      out += (n & 4) ? Z1 : Z0;
      out += (n & 2) ? Z1 : Z0;
      out += (n & 1) ? Z1 : Z0;
    }
    return out;
  }

  function decodeIdFromLine(line) {
    const s = String(line || "");

    // legacy: "...<LEGACY_INV><id>"
    if (s.includes(LEGACY_INV)) {
      const idx = s.indexOf(LEGACY_INV);
      return s.slice(idx + LEGACY_INV.length).trim() || null;
    }

    const p = s.indexOf(PFX);
    if (p === -1) return null;

    const tail = s.slice(p + PFX.length);
    const bits = [];
    for (const ch of tail) {
      if (ch === Z0) bits.push(0);
      else if (ch === Z1) bits.push(1);
      else break;
    }
    if (bits.length < 32) return null;

    let hex = "";
    for (let i = 0; i < 32; i += 4) {
      const nib = (bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3];
      hex += nib.toString(16);
    }
    return hex;
  }

  function isBlank(line) {
    return !String(line || "").trim();
  }

  function isComment(line) {
    return String(line || "").trim().startsWith("#");
  }

  function isMarkerLine(line) {
    const s = String(line || "");
    return (s.includes(MARKER_VISIBLE) && (s.includes(PFX) || s.includes(LEGACY_INV)));
  }

  // marker lines MUST be treated as meaningful (not skippable comments)
  function isSkippable(line) {
    if (isBlank(line)) return true;
    if (isMarkerLine(line)) return false;
    return isComment(line);
  }

  function lineIndent(line) {
    const m = String(line || "").match(/^(\s*)/);
    return m ? m[1].length : 0;
  }

  function clamp(n, lo, hi) {
    return Math.max(lo, Math.min(hi, n));
  }

  function buildLineStarts(lines) {
    const starts = [];
    let pos = 0;
    for (let i = 0; i < lines.length; i += 1) {
      starts.push(pos);
      pos += lines[i].length + 1; // + "\n"
    }
    return starts;
  }

  function computeSelectionAfterReplace(oldText, oldLines, replaceStartLine, replaceEndLine, newLines, visibleCaretPosInMarker) {
    const oldStarts = buildLineStarts(oldLines);
    const oldStart = oldStarts[replaceStartLine] ?? 0;
    const oldEnd = (replaceEndLine < oldLines.length)
      ? (oldStarts[replaceEndLine] ?? oldText.length)
      : oldText.length;

    const newText = newLines.join("\n");
    const delta = newText.length - oldText.length;

    function mapPos(pos) {
      if (pos <= oldStart) return pos;
      if (pos >= oldEnd) return pos + delta;
      return oldStart + (visibleCaretPosInMarker ?? 0);
    }

    return { mapPos, oldStart, oldEnd, newText };
  }

  function restoreViewStable(el, selStart, selEnd, scrollTop, scrollLeft) {
    requestAnimationFrame(() => {
      try {
        const len = (el.value || "").length;
        const ss = clamp(selStart, 0, len);
        const se = clamp(selEnd, 0, len);
        el.setSelectionRange(ss, se);
      } catch { /* ignore */ }

      requestAnimationFrame(() => {
        try {
          el.scrollTop = scrollTop;
          el.scrollLeft = scrollLeft;
        } catch { /* ignore */ }
      });
    });
  }

  function computeFoldables(lines) {
    const out = [];

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i] || "";
      if (isSkippable(line)) continue;
      if (line.trimStart().startsWith("-")) continue;

      const m = line.match(/^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$/);
      if (!m) continue;

      const indent = m[1].length;

      let j = i + 1;
      while (j < lines.length && isSkippable(lines[j])) j += 1;
      if (j >= lines.length) continue;

      const child = lines[j] || "";
      const childIndent = lineIndent(child);
      const childIsDash = child.trimStart().startsWith("-");

      if (isMarkerLine(child)) {
        let end = lines.length;
        for (let k = j + 1; k < lines.length; k += 1) {
          const l2 = lines[k] || "";
          if (isSkippable(l2)) continue;
          const ind2 = lineIndent(l2);
          const dash2 = l2.trimStart().startsWith("-");
          if (ind2 < indent) { end = k; break; }
          if (ind2 === indent && !dash2) { end = k; break; }
        }
        out.push({ keyLine: i, indent, childStart: j, childEnd: end, kind: "collapsed" });
        continue;
      }

      if (childIndent > indent) {
        let end = lines.length;
        for (let k = j; k < lines.length; k += 1) {
          const l2 = lines[k] || "";
          if (isSkippable(l2)) continue;
          if (lineIndent(l2) <= indent) { end = k; break; }
        }
        out.push({ keyLine: i, indent, childStart: i + 1, childEnd: end, kind: "block" });
        continue;
      }

      if (childIndent === indent && childIsDash) {
        let end = lines.length;
        for (let k = j; k < lines.length; k += 1) {
          const l2 = lines[k] || "";
          if (isSkippable(l2)) continue;
          const ind2 = lineIndent(l2);
          const dash2 = l2.trimStart().startsWith("-");
          if (ind2 < indent) { end = k; break; }
          if (ind2 === indent && !dash2) { end = k; break; }
        }
        out.push({ keyLine: i, indent, childStart: i + 1, childEnd: end, kind: "seq" });
        continue;
      }
    }

    return out;
  }

  function ensureWrapper(textarea) {
    let wrap = textarea.closest(".wf2fold-wrap");
    if (wrap) return wrap;

    wrap = document.createElement("div");
    wrap.className = "wf2fold-wrap";
    wrap.style.position = "relative";
    wrap.style.display = "block";
    wrap.style.width = "100%";
    wrap.style.isolation = "isolate";

    // ✅ IMPORTANT: clip gutter buttons to the textarea box
    wrap.style.overflow = "hidden";

    textarea.parentNode.insertBefore(wrap, textarea);
    wrap.appendChild(textarea);

    textarea.style.position = "relative";
    textarea.style.zIndex = "1";

    const curPadLeft = parseInt(getComputedStyle(textarea).paddingLeft || "0", 10) || 0;
    textarea.style.paddingLeft = (curPadLeft + 22) + "px";

    if (!document.getElementById("wf2fold-style")) {
      const style = document.createElement("style");
      style.id = "wf2fold-style";
      style.textContent = `
        .wf2fold-toggle{
          position:absolute;
          left: 6px;
          width: 16px; height: 16px;
          display:flex; align-items:center; justify-content:center;
          border-radius: 4px;
          cursor: pointer;
          user-select:none;
          font-size: 12px;
          line-height: 1;
          z-index: 5;
          opacity: .95;
          background: rgba(255,255,255,.12);
          border: 1px solid rgba(255,255,255,.22);
        }
        .wf2fold-toggle:hover{ opacity: 1; background: rgba(255,255,255,.18); }
      `;
      document.head.appendChild(style);
    }

    return wrap;
  }

  function getLineHeightPx(textarea) {
    const cs = getComputedStyle(textarea);
    let lh = parseFloat(cs.lineHeight);
    if (!Number.isFinite(lh)) lh = (parseFloat(cs.fontSize) || 14) * 1.35;
    return lh;
  }

  function getTopInsetPx(textarea) {
    const cs = getComputedStyle(textarea);
    const padTop = parseFloat(cs.paddingTop) || 0;
    const borderTop = parseFloat(cs.borderTopWidth) || 0;
    // small extra to align better visually with the text baseline
    return padTop + borderTop;
  }

  function isCollapsedAt(textarea, foldable) {
    const lines = textarea.value.split("\n");

    const direct = lines[foldable.childStart] || "";
    if (isMarkerLine(direct)) return true;

    let j = foldable.keyLine + 1;
    while (j < lines.length && isSkippable(lines[j])) j += 1;
    return j < lines.length && isMarkerLine(lines[j]);
  }

  function collapseAt(textarea, foldable) {
    const oldText = String(textarea.value || "");
    const oldLines = oldText.split("\n");
    if (isCollapsedAt(textarea, foldable)) return false;

    const scrollTop = textarea.scrollTop;
    const scrollLeft = textarea.scrollLeft;
    const selStart = textarea.selectionStart ?? 0;
    const selEnd = textarea.selectionEnd ?? 0;

    const id = makeIdHex8();
    const originalLines = oldLines.slice(foldable.childStart, foldable.childEnd);
    foldStore.set(id, { originalLines });

    const hiddenCount = originalLines.length;
    const indentSpaces = " ".repeat(foldable.indent + 2);

    const markerVisible = `${MARKER_VISIBLE} (${hiddenCount} line${hiddenCount === 1 ? "" : "s"})`;
    const payload = encodeId(id);

    const marker = `${indentSpaces}${markerVisible}${payload}`;
    const caretOffsetInMarker = (indentSpaces + markerVisible).length;

    const newLines = oldLines.slice();
    newLines.splice(foldable.childStart, originalLines.length, marker);

    const rep = computeSelectionAfterReplace(
      oldText,
      oldLines,
      foldable.childStart,
      foldable.childEnd,
      newLines,
      caretOffsetInMarker
    );

    const newSelStart = rep.mapPos(selStart);
    const newSelEnd = rep.mapPos(selEnd);

    textarea.value = rep.newText;
    textarea.dispatchEvent(new Event("input", { bubbles: true }));

    restoreViewStable(textarea, newSelStart, newSelEnd, scrollTop, scrollLeft);
    return true;
  }

  function expandMarkerAtLine(textarea, lineIndex) {
    const oldText = String(textarea.value || "");
    const oldLines = oldText.split("\n");
    const line = oldLines[lineIndex] || "";
    const id = decodeIdFromLine(line);
    if (!id) return false;

    const rec = foldStore.get(id);
    if (!rec) return false;

    const scrollTop = textarea.scrollTop;
    const scrollLeft = textarea.scrollLeft;
    const selStart = textarea.selectionStart ?? 0;
    const selEnd = textarea.selectionEnd ?? 0;

    const newLines = oldLines.slice();
    newLines.splice(lineIndex, 1, ...rec.originalLines);
    foldStore.delete(id);

    const rep = computeSelectionAfterReplace(
      oldText,
      oldLines,
      lineIndex,
      lineIndex + 1,
      newLines,
      0
    );

    const newSelStart = rep.mapPos(selStart);
    const newSelEnd = rep.mapPos(selEnd);

    textarea.value = rep.newText;
    textarea.dispatchEvent(new Event("input", { bubbles: true }));

    restoreViewStable(textarea, newSelStart, newSelEnd, scrollTop, scrollLeft);
    return true;
  }

  function expandAt(textarea, foldable) {
    const lines = textarea.value.split("\n");

    const candidates = [];
    if (foldable.childStart >= 0 && foldable.childStart < lines.length) candidates.push(foldable.childStart);

    let j = foldable.keyLine + 1;
    while (j < lines.length && isSkippable(lines[j])) j += 1;
    if (j < lines.length) candidates.push(j);

    for (const idx of candidates) {
      if (isMarkerLine(lines[idx])) return expandMarkerAtLine(textarea, idx);
    }
    return false;
  }

  function expandAll(textarea) {
    const lines = textarea.value.split("\n");
    let changed = false;

    for (let i = 0; i < lines.length; i += 1) {
      if (!isMarkerLine(lines[i])) continue;
      const id = decodeIdFromLine(lines[i]);
      if (!id) continue;

      const rec = foldStore.get(id);
      if (!rec) continue;

      lines.splice(i, 1, ...rec.originalLines);
      foldStore.delete(id);
      changed = true;
      i = Math.max(-1, i - 1);
    }

    if (changed) {
      const scrollTop = textarea.scrollTop;
      const scrollLeft = textarea.scrollLeft;
      const selStart = textarea.selectionStart ?? 0;
      const selEnd = textarea.selectionEnd ?? 0;

      textarea.value = lines.join("\n");
      textarea.dispatchEvent(new Event("input", { bubbles: true }));

      restoreViewStable(textarea, selStart, selEnd, scrollTop, scrollLeft);
    }
    return changed;
  }

  function renderGutter(textarea) {
    const wrap = ensureWrapper(textarea);
    wrap.querySelectorAll(".wf2fold-toggle").forEach((n) => n.remove());

    const lines = textarea.value.split("\n");
    const foldables = computeFoldables(lines);

    const lh = getLineHeightPx(textarea);
    const scrollTop = textarea.scrollTop;

    const viewTopLine = Math.floor(scrollTop / lh);
    const viewLines = Math.ceil(textarea.clientHeight / lh) + 2;
    const viewBottomLine = viewTopLine + viewLines;

    const topInset = getTopInsetPx(textarea);
    const btnH = 16;
    const maxY = Math.max(0, textarea.clientHeight - btnH);

    foldables.forEach((f) => {
      if (f.keyLine < viewTopLine || f.keyLine > viewBottomLine) return;

      // ✅ align to textarea content box and clamp to visible viewport
      const y = topInset + (f.keyLine * lh) - scrollTop + Math.max(0, (lh - btnH) / 2);

      if (y < 0 || y > maxY) return; // don't render outside

      const btn = document.createElement("div");
      btn.className = "wf2fold-toggle";
      btn.style.top = y + "px";
      btn.title = "Collapse/Expand";
      btn.textContent = isCollapsedAt(textarea, f) ? "▸" : "▾";

      btn.addEventListener("click", (e) => {
        e.preventDefault();
        e.stopPropagation();

        const curLines = textarea.value.split("\n");
        const curFoldables = computeFoldables(curLines);
        const cur = curFoldables.find((x) => x.keyLine === f.keyLine);
        if (!cur) return;

        if (isCollapsedAt(textarea, cur)) expandAt(textarea, cur);
        else collapseAt(textarea, cur);

        renderGutter(textarea);
      });

      wrap.appendChild(btn);
    });
  }

  WF2CC.folding.init = function init(textarea) {
    if (!textarea) return;

    ensureWrapper(textarea);
    renderGutter(textarea);

    const rer = WF2CC.debounce
      ? WF2CC.debounce(() => renderGutter(textarea), 80)
      : () => renderGutter(textarea);

    textarea.addEventListener("scroll", () => renderGutter(textarea));
    textarea.addEventListener("input", rer);

    WF2CC.folding.refresh = () => renderGutter(textarea);
    WF2CC.folding.expandAll = () => expandAll(textarea);
  };
})();