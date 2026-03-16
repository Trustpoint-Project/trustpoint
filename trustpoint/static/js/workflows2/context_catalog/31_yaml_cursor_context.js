// static/js/workflows2/context_catalog/31_yaml_cursor_context.js
(function () {
  if (!window.WF2CC) return;
  const WF2CC = window.WF2CC;

  function lineIndent(line) {
    const m = String(line || "").match(/^(\s*)/);
    return m ? m[1].length : 0;
  }

  function isBlankOrComment(line) {
    const t = String(line || "").trim();
    return !t || t.startsWith("#");
  }

  function isInsideBlockAtCursor(lines, cursorLine, block) {
    if (!block) return false;
    if (cursorLine < block.start || cursorLine >= block.end) return false;

    const line = lines[cursorLine] || "";
    if (!isBlankOrComment(line)) return true;

    const ind = lineIndent(line);
    return ind > (block.indent ?? 0);
  }

  // ✅ UPDATED: allow dotted keys like "vars.http_status" / "headers.x-request-id"
  function parseCurrentKeyAndValueMode(line, col) {
    const raw = String(line || "");
    const t = raw.trimStart();

    if (t.startsWith("-")) return { currentKey: null, inValue: false };

    const colon = t.indexOf(":");
    if (colon === -1) return { currentKey: null, inValue: false };

    const key = t.slice(0, colon).trim();

    // ✅ allow keys like "vars.http_status"
    if (!/^[A-Za-z_][A-Za-z0-9_.-]*$/.test(key)) return { currentKey: null, inValue: false };

    const leading = raw.length - t.length;
    const relCol = Math.max(0, Number(col || 0) - leading);

    // ✅ treat cursor at/after ":" as "in value" (so picker shows right after typing colon)
    const inValue = relCol >= colon + 1;

    return { currentKey: key, inValue };
  }

  WF2CC.yaml.getCursorContext = function getCursorContext(yamlText, cursorIndex) {
    const text = String(yamlText || "");
    const lines = text.split(/\r?\n/);

    const cursor = WF2CC.yaml.indexToLineCol(text, cursorIndex);
    const blocks = WF2CC.yaml.buildBlocks(lines);

    const triggerOn = WF2CC.yaml.parseTriggerOn(lines, blocks.triggerBlock);
    const indents = WF2CC.yaml.computeIndents(blocks);

    const stepInfo = blocks.stepsBlock
      ? WF2CC.yaml.findEnclosingStep(lines, cursor.line, blocks.stepsBlock, indents.stepItem)
      : null;

    const anchors = WF2CC.yaml.computeAnchors(lines, blocks, stepInfo);
    const stepIds = WF2CC.yaml.findStepIds(lines, blocks.stepsBlock, indents.stepItem);

    const applyLineNo = blocks.applyBlock ? blocks.applyBlock.start : null;
    const applyInlineList = !!(blocks.applyBlock && String(blocks.applyBlock.rawValue || "").trim() === "[]");

    const flowInlineList = !!(blocks.flowRawValue && String(blocks.flowRawValue || "").trim() === "[]");

    let area = "root";
    let pill = "root";
    let varInsertMode = "template";

    let currentKey = null;
    let inValue = false;

    if (WF2CC.yaml.isInsideTemplateExpr(text, cursorIndex)) {
      area = "expression";
      pill = "expr";
      varInsertMode = "expr_inner";
      return {
        triggerOn, area, pill, lineNo: cursor.line,
        applyLineNo, applyInlineList,
        flowLineNo: blocks.flowLineNo ?? null, flowInlineList,
        stepType: stepInfo ? stepInfo.stepType : null,
        stepId: stepInfo ? stepInfo.stepId : null,
        stepIds,
        varInsertMode, indents, anchors, cursor,
        currentKey, inValue,
      };
    }

    if (blocks.triggerBlock && WF2CC.yaml.insideRange(cursor.line, blocks.triggerBlock.start, blocks.triggerBlock.end)) {
      const line = lines[cursor.line] || "";
      const t = line.trimStart();

      if (/^\s*on\s*:/.test(t)) {
        area = "trigger.on";
        pill = "trigger.on";
      } else if (isInsideBlockAtCursor(lines, cursor.line, blocks.sourcesBlock) || /^\s*sources\s*:/.test(t)) {
        area = "trigger.sources";
        pill = "trigger.sources";
      } else {
        area = "trigger";
        pill = "trigger";
      }

      return {
        triggerOn, area, pill, lineNo: cursor.line,
        applyLineNo, applyInlineList,
        flowLineNo: blocks.flowLineNo ?? null, flowInlineList,
        stepType: stepInfo ? stepInfo.stepType : null,
        stepId: stepInfo ? stepInfo.stepId : null,
        stepIds,
        varInsertMode, indents, anchors, cursor,
        currentKey, inValue,
      };
    }

    if (blocks.applyBlock && isInsideBlockAtCursor(lines, cursor.line, blocks.applyBlock)) {
      area = "apply";
      pill = "apply";
      return {
        triggerOn, area, pill, lineNo: cursor.line,
        applyLineNo, applyInlineList,
        flowLineNo: blocks.flowLineNo ?? null, flowInlineList,
        stepType: stepInfo ? stepInfo.stepType : null,
        stepId: stepInfo ? stepInfo.stepId : null,
        stepIds,
        varInsertMode, indents, anchors, cursor,
        currentKey, inValue,
      };
    }

    if (blocks.workflowBlock && WF2CC.yaml.insideRange(cursor.line, blocks.workflowBlock.start, blocks.workflowBlock.end)) {
      if (blocks.workflowStartLine !== null && cursor.line === blocks.workflowStartLine) {
        area = "workflow.start";
        pill = "workflow.start";
      } else if (blocks.stepsBlock && isInsideBlockAtCursor(lines, cursor.line, blocks.stepsBlock)) {
        const kv = parseCurrentKeyAndValueMode(lines[cursor.line] || "", cursor.col);
        currentKey = kv.currentKey;
        inValue = kv.inValue;

        if (stepInfo && stepInfo.stepType) {
          const typ = String(stepInfo.stepType);

          if (typ === "webhook" && stepInfo.captureBlock && isInsideBlockAtCursor(lines, cursor.line, stepInfo.captureBlock)) {
            area = "workflow.steps.webhook.capture";
            pill = "webhook.capture";
          } else if (typ === "logic" && stepInfo.casesBlock && isInsideBlockAtCursor(lines, cursor.line, stepInfo.casesBlock)) {
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
      } else if (blocks.flowBlock && isInsideBlockAtCursor(lines, cursor.line, blocks.flowBlock)) {
        const tt = (lines[cursor.line] || "").trimStart();
        if (/\bfrom\s*:/.test(tt)) area = "workflow.flow.from";
        else if (/\bto\s*:/.test(tt)) area = "workflow.flow.to";
        else if (/\bon\s*:/.test(tt)) area = "workflow.flow.on";
        else area = "workflow.flow";
        pill = "workflow.flow";
      } else {
        area = "workflow";
        pill = "workflow";
      }

      return {
        triggerOn, area, pill, lineNo: cursor.line,
        applyLineNo, applyInlineList,
        flowLineNo: blocks.flowLineNo ?? null, flowInlineList,
        stepType: stepInfo ? stepInfo.stepType : null,
        stepId: stepInfo ? stepInfo.stepId : null,
        stepIds,
        varInsertMode, indents, anchors, cursor,
        currentKey, inValue,
      };
    }

    return {
      triggerOn, area, pill, lineNo: cursor.line,
      applyLineNo, applyInlineList,
      flowLineNo: blocks.flowLineNo ?? null, flowInlineList,
      stepType: stepInfo ? stepInfo.stepType : null,
      stepId: stepInfo ? stepInfo.stepId : null,
      stepIds,
      varInsertMode, indents, anchors, cursor,
      currentKey, inValue,
    };
  };

  WF2CC.getCursorContext = WF2CC.yaml.getCursorContext;
})();