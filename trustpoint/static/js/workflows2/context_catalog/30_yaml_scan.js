// static/js/workflows2/context_catalog/30_yaml_scan.js
(function () {
  if (!window.WF2CC) return;
  const WF2CC = window.WF2CC;

  function lineIndent(line) {
    let n = 0;
    for (let i = 0; i < line.length; i += 1) {
      const ch = line[i];
      if (ch === " ") n += 1;
      else if (ch === "\t") n += 2;
      else break;
    }
    return n;
  }

  function isBlankOrComment(line) {
    const t = String(line || "").trim();
    return !t || t.startsWith("#");
  }

  function indexToLineCol(text, idx) {
    const s = String(text || "");
    const i = Math.max(0, Math.min(Number(idx || 0), s.length));
    const head = s.slice(0, i);
    const parts = head.split(/\r?\n/);
    const line = parts.length - 1;
    const col = parts[parts.length - 1].length;
    return { line, col };
  }

  function escRe(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function findKeyLine(lines, key, startLine, endLine, indentWanted) {
    const re = new RegExp("^(\\s*)" + escRe(key) + "\\s*:\\s*(.*)$");
    for (let i = startLine; i < endLine; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      const m = line.match(re);
      if (!m) continue;
      const ind = m[1].length;
      if (typeof indentWanted === "number" && ind !== indentWanted) continue;
      if (line.trimStart().startsWith("-")) continue;
      return { line: i, indent: ind, rawValue: (m[2] || "").trim() };
    }
    return null;
  }

  function findBlockEnd(lines, startLine, startIndent) {
    for (let i = startLine + 1; i < lines.length; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      if (lineIndent(line) <= startIndent) return i;
    }
    return lines.length;
  }

  function unquote(s) {
    const v = String(s || "").trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      return v.slice(1, -1);
    }
    return v;
  }

  function insideRange(lineNo, start, end) {
    return typeof start === "number" && typeof end === "number" && lineNo >= start && lineNo < end;
  }

  function parseTriggerOn(lines, triggerBlock) {
    if (!triggerBlock) return null;
    for (let i = triggerBlock.start + 1; i < triggerBlock.end; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      const m = line.match(/^\s*on\s*:\s*([^#]+?)\s*$/);
      if (m) {
        const v = unquote(m[1]);
        if (!v) return null;
        if (v === "trigger") return null;
        if (v.includes("__")) return null;
        return v;
      }
    }
    return null;
  }

  function isInsideTemplateExpr(text, cursorIdx) {
    const s = String(text || "");
    const i = Math.max(0, Math.min(Number(cursorIdx || 0), s.length));

    const before = s.slice(0, i);
    const openIdx = before.lastIndexOf("${");
    if (openIdx < 0) return false;

    const between = before.slice(openIdx);
    if (between.includes("}")) return false;

    const after = s.slice(i);
    if (!after.includes("}")) return false;

    return true;
  }

  function buildBlocks(lines) {
    const rootStart = 0;
    const rootEnd = lines.length;

    const trig = findKeyLine(lines, "trigger", rootStart, rootEnd, 0);
    const triggerBlock = trig
      ? { start: trig.line, indent: trig.indent, end: findBlockEnd(lines, trig.line, trig.indent) }
      : null;

    let sourcesBlock = null;
    if (triggerBlock) {
      const sourcesLine = findKeyLine(lines, "sources", triggerBlock.start + 1, triggerBlock.end, null);
      if (sourcesLine) {
        sourcesBlock = {
          start: sourcesLine.line,
          indent: sourcesLine.indent,
          end: findBlockEnd(lines, sourcesLine.line, sourcesLine.indent),
        };
      }
    }

    const apply = findKeyLine(lines, "apply", rootStart, rootEnd, 0);
    const applyBlock = apply
      ? { start: apply.line, indent: apply.indent, end: findBlockEnd(lines, apply.line, apply.indent), rawValue: apply.rawValue }
      : null;

    const wf = findKeyLine(lines, "workflow", rootStart, rootEnd, 0);
    const workflowBlock = wf
      ? { start: wf.line, indent: wf.indent, end: findBlockEnd(lines, wf.line, wf.indent) }
      : null;

    let stepsBlock = null;
    let flowBlock = null;
    let workflowStartLine = null;
    let flowLineNo = null;
    let flowRawValue = null;

    if (workflowBlock) {
      const steps = findKeyLine(lines, "steps", workflowBlock.start + 1, workflowBlock.end, null);
      if (steps) stepsBlock = { start: steps.line, indent: steps.indent, end: findBlockEnd(lines, steps.line, steps.indent) };

      const flow = findKeyLine(lines, "flow", workflowBlock.start + 1, workflowBlock.end, null);
      if (flow) {
        flowBlock = { start: flow.line, indent: flow.indent, end: findBlockEnd(lines, flow.line, flow.indent) };
        flowLineNo = flow.line;
        flowRawValue = flow.rawValue;
      }

      const st = findKeyLine(lines, "start", workflowBlock.start + 1, workflowBlock.end, null);
      if (st) workflowStartLine = st.line;
    }

    return {
      triggerBlock, sourcesBlock,
      applyBlock,
      workflowBlock, stepsBlock, flowBlock,
      workflowStartLine,
      flowLineNo, flowRawValue,
    };
  }

  // numeric counts (spaces)
  function computeIndents(blocks) {
    const indentUnitStr = (WF2CC.config?.indent || "  ");
    const indentUnit = indentUnitStr.replace(/\t/g, "  ").length;

    const triggerChild = (blocks.triggerBlock?.indent ?? 0) + indentUnit;
    const sourcesEntry = (blocks.sourcesBlock?.indent ?? triggerChild) + indentUnit;
    const sourcesListItem = sourcesEntry + indentUnit;

    const applyItem = (blocks.applyBlock?.indent ?? 0) + indentUnit;

    const wfChild = (blocks.workflowBlock?.indent ?? 0) + indentUnit;

    const stepItem = (blocks.stepsBlock?.indent ?? wfChild) + indentUnit;
    const stepField = stepItem + indentUnit;

    const flowItem = (blocks.flowBlock?.indent ?? wfChild) + indentUnit;

    const captureEntry = stepField + indentUnit;
    const casesItem = stepField + indentUnit;

    return {
      indentUnit,
      triggerChild,
      sourcesEntry,
      sourcesListItem,
      applyItem,
      wfChild,
      stepItem,
      stepField,
      flowItem,
      captureEntry,
      casesItem,
    };
  }

  function findStepIds(lines, stepsBlock, stepItemIndent) {
    if (!stepsBlock) return [];
    const out = [];
    const stepHeaderRe = new RegExp("^(\\s{" + stepItemIndent + "})([^\\s:#]+)\\s*:\\s*$");
    for (let i = stepsBlock.start + 1; i < stepsBlock.end; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      const m = line.match(stepHeaderRe);
      if (!m) continue;
      const id = m[2];
      if (!id) continue;
      if (id.includes("__")) continue;
      out.push(id);
    }
    return out;
  }

  function findStepById(lines, stepsBlock, stepItemIndent, stepId) {
    if (!stepsBlock || !stepId) return null;
    const want = String(stepId);
    const stepHeaderRe = new RegExp("^(\\s{" + stepItemIndent + "})" + escRe(want) + "\\s*:\\s*$");

    for (let i = stepsBlock.start + 1; i < stepsBlock.end; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      if (!stepHeaderRe.test(line)) continue;

      let stepEnd = stepsBlock.end;
      const anyStepHeaderRe = new RegExp("^(\\s{" + stepItemIndent + "})([^\\s:#]+)\\s*:\\s*$");
      for (let j = i + 1; j < stepsBlock.end; j += 1) {
        const l2 = lines[j] || "";
        if (isBlankOrComment(l2)) continue;
        if (anyStepHeaderRe.test(l2)) { stepEnd = j; break; }
      }

      let stepType = null;
      for (let j = i + 1; j < stepEnd; j += 1) {
        const l2 = lines[j] || "";
        if (isBlankOrComment(l2)) continue;
        const m = l2.match(/^\s*type\s*:\s*([^#\s]+)\s*$/);
        if (m) { stepType = unquote(m[1]); break; }
      }

      return { stepId: want, stepType, start: i, end: stepEnd };
    }
    return null;
  }

  function findEnclosingStep(lines, cursorLine, stepsBlock, stepItemIndent) {
    if (!stepsBlock) return null;

    let stepStart = null;
    let stepId = null;

    const stepHeaderRe = new RegExp("^(\\s{" + stepItemIndent + "})([^\\s:#]+)\\s*:\\s*$");

    for (let i = stepsBlock.start + 1; i < stepsBlock.end; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      const m = line.match(stepHeaderRe);
      if (m) {
        if (i <= cursorLine) {
          stepStart = i;
          stepId = m[2];
        } else break;
      }
    }

    if (stepStart === null) return null;

    let stepEnd = stepsBlock.end;
    for (let i = stepStart + 1; i < stepsBlock.end; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      const m = line.match(stepHeaderRe);
      if (m) { stepEnd = i; break; }
    }

    if (!(cursorLine >= stepStart && cursorLine < stepEnd)) return null;

    let stepType = null;
    for (let i = stepStart + 1; i < stepEnd; i += 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;
      const m = line.match(/^\s*type\s*:\s*([^#\s]+)\s*$/);
      if (m) { stepType = unquote(m[1]); break; }
    }

    const captureLine = findKeyLine(lines, "capture", stepStart + 1, stepEnd, null);
    const casesLine = findKeyLine(lines, "cases", stepStart + 1, stepEnd, null);

    const captureBlock = captureLine
      ? { start: captureLine.line, indent: captureLine.indent, end: findBlockEnd(lines, captureLine.line, captureLine.indent) }
      : null;

    const casesBlock = casesLine
      ? { start: casesLine.line, indent: casesLine.indent, end: findBlockEnd(lines, casesLine.line, casesLine.indent) }
      : null;

    return { stepId, stepType, start: stepStart, end: stepEnd, captureBlock, casesBlock };
  }

  function computeAnchors(lines, blocks, stepInfo) {
    return {
      triggerEndLine: blocks.triggerBlock ? blocks.triggerBlock.end : lines.length,
      sourcesEndLine: blocks.sourcesBlock ? blocks.sourcesBlock.end : (blocks.triggerBlock ? blocks.triggerBlock.end : lines.length),
      applyEndLine: blocks.applyBlock ? blocks.applyBlock.end : lines.length,
      stepsEndLine: blocks.stepsBlock ? blocks.stepsBlock.end : lines.length,
      flowEndLine: blocks.flowBlock ? blocks.flowBlock.end : lines.length,
      workflowHeadLine: blocks.workflowBlock ? (blocks.workflowBlock.start + 1) : lines.length,
      stepEndLine: stepInfo ? stepInfo.end : null,
      captureEndLine: stepInfo?.captureBlock ? stepInfo.captureBlock.end : null,
      casesEndLine: stepInfo?.casesBlock ? stepInfo.casesBlock.end : null,
    };
  }

  function findAreaLine(lines, blocks, area) {
    const a = String(area || "");
    if (!a) return null;

    if (a === "trigger" || a.startsWith("trigger")) return blocks.triggerBlock?.start ?? null;
    if (a === "apply") return blocks.applyBlock?.start ?? null;
    if (a === "workflow" || a.startsWith("workflow")) return blocks.workflowBlock?.start ?? null;
    if (a.startsWith("workflow.flow")) return blocks.flowBlock?.start ?? null;
    if (a.startsWith("workflow.steps")) return blocks.stepsBlock?.start ?? null;

    return null;
  }

  // export helpers
  WF2CC.yaml._lineIndent = lineIndent;
  WF2CC.yaml._isBlankOrComment = isBlankOrComment;

  WF2CC.yaml.indexToLineCol = indexToLineCol;
  WF2CC.yaml.insideRange = insideRange;
  WF2CC.yaml.isInsideTemplateExpr = isInsideTemplateExpr;

  WF2CC.yaml.findKeyLine = findKeyLine;
  WF2CC.yaml.findBlockEnd = findBlockEnd;
  WF2CC.yaml.unquote = unquote;

  WF2CC.yaml.buildBlocks = buildBlocks;
  WF2CC.yaml.computeIndents = computeIndents;
  WF2CC.yaml.computeAnchors = computeAnchors;

  WF2CC.yaml.parseTriggerOn = parseTriggerOn;
  WF2CC.yaml.findStepIds = findStepIds;
  WF2CC.yaml.findEnclosingStep = findEnclosingStep;
  WF2CC.yaml.findStepById = findStepById;
  WF2CC.yaml.findAreaLine = findAreaLine;
})();