// static/js/workflows2/context_catalog/03_yaml_context.js
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
    if ((v.startsWith("\"") && v.endsWith("\"")) || (v.startsWith("'") && v.endsWith("'"))) {
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
    const indentUnit = (WF2CC.config?.indent || "  ").replace(/\t/g, "  ").length;

    const triggerChild = (blocks.triggerBlock?.indent ?? 0) + indentUnit;
    const sourcesEntry = (blocks.sourcesBlock?.indent ?? triggerChild) + indentUnit;

    const applyItem = (blocks.applyBlock?.indent ?? 0) + indentUnit;

    const wfChild = (blocks.workflowBlock?.indent ?? 0) + indentUnit;

    const stepItem = (blocks.stepsBlock?.indent ?? wfChild) + indentUnit;
    const stepField = stepItem + indentUnit;

    const flowItem = (blocks.flowBlock?.indent ?? wfChild) + indentUnit;

    const captureEntry = stepField + indentUnit;
    const casesItem = stepField + indentUnit;

    return {
      triggerChild,
      sourcesEntry,
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

  WF2CC.getCursorContext = function getCursorContext(yamlText, cursorIndex) {
    const text = String(yamlText || "");
    const lines = text.split(/\r?\n/);

    const cursor = indexToLineCol(text, cursorIndex);
    const blocks = buildBlocks(lines);

    const triggerOn = parseTriggerOn(lines, blocks.triggerBlock);
    const indents = computeIndents(blocks);

    const stepInfo = blocks.stepsBlock ? findEnclosingStep(lines, cursor.line, blocks.stepsBlock, indents.stepItem) : null;
    const anchors = computeAnchors(lines, blocks, stepInfo);
    const stepIds = findStepIds(lines, blocks.stepsBlock, indents.stepItem);

    const applyLineNo = blocks.applyBlock ? blocks.applyBlock.start : null;
    const applyInlineList = !!(blocks.applyBlock && String(blocks.applyBlock.rawValue || "").trim() === "[]");

    const flowInlineList = !!(blocks.flowRawValue && String(blocks.flowRawValue || "").trim() === "[]");

    let area = "root";
    let pill = "root";
    let varInsertMode = "template";

    if (isInsideTemplateExpr(text, cursorIndex)) {
      area = "expression";
      pill = "expr";
      varInsertMode = "expr_inner";
    } else if (blocks.triggerBlock && insideRange(cursor.line, blocks.triggerBlock.start, blocks.triggerBlock.end)) {
      const line = lines[cursor.line] || "";
      if (/^\s*on\s*:/.test(line.trimStart())) { area = "trigger.on"; pill = "trigger.on"; }
      else if (
        /^\s*sources\s*:/.test(line.trimStart()) ||
        (blocks.sourcesBlock && insideRange(cursor.line, blocks.sourcesBlock.start, blocks.sourcesBlock.end))
      ) { area = "trigger.sources"; pill = "trigger.sources"; }
      else { area = "trigger"; pill = "trigger"; }
    } else if (blocks.applyBlock && insideRange(cursor.line, blocks.applyBlock.start, blocks.applyBlock.end)) {
      area = "apply";
      pill = "apply";
    } else if (blocks.workflowBlock && insideRange(cursor.line, blocks.workflowBlock.start, blocks.workflowBlock.end)) {
      if (blocks.workflowStartLine !== null && cursor.line === blocks.workflowStartLine) {
        area = "workflow.start";
        pill = "workflow.start";
      } else if (blocks.stepsBlock && insideRange(cursor.line, blocks.stepsBlock.start, blocks.stepsBlock.end)) {
        if (stepInfo && stepInfo.stepType) {
          const typ = String(stepInfo.stepType);
          if (typ === "webhook" && stepInfo.captureBlock && insideRange(cursor.line, stepInfo.captureBlock.start, stepInfo.captureBlock.end)) {
            area = "workflow.steps.webhook.capture";
            pill = "webhook.capture";
            varInsertMode = "vars_target";
          } else if (typ === "logic" && stepInfo.casesBlock && insideRange(cursor.line, stepInfo.casesBlock.start, stepInfo.casesBlock.end)) {
            area = "workflow.steps.logic.cases";
            pill = "logic.cases";
          } else {
            area = "workflow.steps." + typ;
            pill = "step:" + typ;
          }
        } else {
          area = "workflow.steps";
          pill = "workflow.steps";
        }
      } else if (blocks.flowBlock && insideRange(cursor.line, blocks.flowBlock.start, blocks.flowBlock.end)) {
        const t = (lines[cursor.line] || "").trimStart();
        if (/\bfrom\s*:/.test(t)) area = "workflow.flow.from";
        else if (/\bto\s*:/.test(t)) area = "workflow.flow.to";
        else if (/\bon\s*:/.test(t)) area = "workflow.flow.on";
        else area = "workflow.flow";
        pill = "workflow.flow";
      } else {
        area = "workflow";
        pill = "workflow";
      }
    }

    return {
      triggerOn,
      area,
      pill,
      lineNo: cursor.line,

      applyLineNo,
      applyInlineList,

      flowLineNo: blocks.flowLineNo ?? null,
      flowInlineList,

      stepType: stepInfo ? stepInfo.stepType : null,
      stepId: stepInfo ? stepInfo.stepId : null,
      stepIds,

      varInsertMode,
      indents,
      anchors,
      cursor,
    };
  };
})();
