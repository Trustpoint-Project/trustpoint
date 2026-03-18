// static/js/workflows2/context_catalog/32_yaml_step_keys.js
(function () {
  const WF2CC = window.WF2CC;
  if (!WF2CC) return;

  // Collect root-level keys inside a step block (type/title/url/method/cc/bcc/...)
  // We only collect keys at ctx.indents.stepField.
  function collectRootKeys(lines, stepInfo, wantedIndent) {
    const out = new Set();
    if (!stepInfo) return out;

    const start = stepInfo.start;
    const end = stepInfo.end;

    for (let i = start + 1; i < end; i += 1) {
      const line = lines[i] || "";
      if (WF2CC.yaml._isBlankOrComment(line)) continue;

      const ind = WF2CC.yaml._lineIndent(line);
      if (ind !== wantedIndent) continue;

      const t = line.trimStart();
      if (t.startsWith("-")) continue;

      const m = t.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*:/);
      if (!m) continue;

      out.add(m[1]);
    }

    return out;
  }

  function getStepInfoFromCtx(lines, ctx, blocks, indents) {
    if (!blocks.stepsBlock) return null;

    // Prefer ctx.stepId (stable even on blank lines)
    const stepId = ctx && ctx.stepId ? String(ctx.stepId) : null;
    if (stepId) {
      const info = WF2CC.yaml.findStepById(lines, blocks.stepsBlock, indents.stepItem, stepId);
      if (info) return info;
    }

    // Fallback: enclosing by cursor line
    const cursorLine = Number(ctx?.lineNo ?? 0);
    return WF2CC.yaml.findEnclosingStep(lines, cursorLine, blocks.stepsBlock, indents.stepItem);
  }

  WF2CC.yaml.getCurrentStepRootKeys = function getCurrentStepRootKeys(yamlText, ctx) {
    const text = String(yamlText || "");
    const lines = text.split(/\r?\n/);

    const blocks = WF2CC.yaml.buildBlocks(lines);
    if (!blocks.stepsBlock) return new Set();

    const indents = WF2CC.yaml.computeIndents(blocks);
    const wantedIndent = Number(ctx?.indents?.stepField ?? indents.stepField ?? 0);

    const stepInfo = getStepInfoFromCtx(lines, ctx, blocks, indents);
    return collectRootKeys(lines, stepInfo, wantedIndent);
  };
})();