// static/js/workflows2/context_catalog/66_value_pickers.js
(function () {
  const WF2CC = window.WF2CC;
  if (!WF2CC) return;

  WF2CC.pickers = WF2CC.pickers || {};

  function isBlankOrComment(line) {
    const t = String(line || "").trim();
    return !t || t.startsWith("#");
  }

  function indentOf(line) {
    const m = String(line || "").match(/^(\s*)/);
    return m ? m[1].length : 0;
  }

  function isListItemLine(line) {
    return /^\s*-\s+/.test(String(line || ""));
  }

  function parseKeyFromMappingLine(line) {
    const raw = String(line || "");
    const t = raw.trimStart();
    if (!t) return null;

    const mDash = t.match(/^-+\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*:/);
    if (mDash) return mDash[1];

    const m = t.match(/^([A-Za-z_][A-Za-z0-9_.-]*)\s*:/);
    if (m) return m[1];

    return null;
  }

  function computeKeyStack(lines, lineNo) {
    const stack = [];
    let curIndent = indentOf(lines[lineNo] || "");

    for (let i = lineNo - 1; i >= 0; i -= 1) {
      const line = lines[i] || "";
      if (isBlankOrComment(line)) continue;

      const ind = indentOf(line);

      if (ind < curIndent) {
        const key = parseKeyFromMappingLine(line);
        if (key) stack.push(key);
        curIndent = ind;
        if (curIndent <= 0) break;
      }
    }

    stack.reverse();
    return stack;
  }

  function getYamlEl() {
    return WF2CC.getYamlTextarea ? WF2CC.getYamlTextarea() : null;
  }

  function getYamlLines() {
    const el = getYamlEl();
    return String(el ? el.value : "").split(/\r?\n/);
  }

  // compute op context helper (unchanged)
  function detectComputeTargetContext(ctx, lines) {
    if (!ctx || ctx.stepType !== "compute") return null;
    const ln = Number(ctx.lineNo ?? -1);
    if (ln < 0 || ln >= lines.length) return null;

    const stack = computeKeyStack(lines, ln);
    if (!stack.includes("set")) return null;

    let i = ln;
    while (i >= 0 && isBlankOrComment(lines[i])) i -= 1;
    if (i < 0) return null;

    for (let j = i; j >= 0 && j > i - 60; j -= 1) {
      const l = lines[j] || "";
      if (isBlankOrComment(l)) continue;

      const m = l.match(/^\s*(vars\.[A-Za-z0-9_.-]+)\s*:\s*$/);
      if (m) {
        const targetIndent = indentOf(l);
        const curIndent = indentOf(lines[ln] || "");
        if (curIndent > targetIndent) return { targetIndent, lineNo: j, target: m[1] };
        return null;
      }

      if (indentOf(l) <= (ctx.indents?.stepField ?? 0) - 2) break;
    }

    return null;
  }

  function captureSourceChoices() {
    return [
      { label: "status_code", value: "status_code", description: "HTTP status code (int)." },
      { label: "body", value: "body", description: "Response body (raw or parsed depending on adapter)." },
      { label: "headers", value: "headers", description: "All response headers (map)." },
      { label: "headers.x-request-id", value: "headers.x-request-id", description: "Single header (example)." },
      { label: "body.some_value", value: "body.some_value", description: "JSON field from body (example)." },
    ];
  }

  function captureTargetChoices() {
    return [
      { label: "vars.http_status", value: "vars.http_status", description: "Store response status code." },
      { label: "vars.http_body", value: "vars.http_body", description: "Store response body." },
      { label: "vars.http_headers", value: "vars.http_headers", description: "Store response headers." },
      { label: "vars.result", value: "vars.result", description: "Generic result variable." },
    ];
  }

  WF2CC.pickers.getPicker = function getPicker(ctx) {
    if (!ctx || !ctx.stepType) return null;

    const stepType = String(ctx.stepType);
    const key = ctx.currentKey ? String(ctx.currentKey) : null;

    const lines = getYamlLines();
    const ln = Number(ctx.lineNo ?? -1);
    const line = (ln >= 0 && ln < lines.length) ? String(lines[ln] || "") : "";
    const stack = (ln >= 0 && ln < lines.length) ? computeKeyStack(lines, ln) : [];

    // ---------------- WEBHOOK CAPTURE ----------------
    if (stepType === "webhook" && String(ctx.area || "") === "workflow.steps.webhook.capture") {
      // blank line inside capture => offer insertion of mappings
      if (!key) {
        return {
          groupTitle: "Capture",
          description: "Insert a capture mapping entry",
          action: "insert_snippet",
          values: [
            // new style (recommended)
            { label: "vars.http_status: status_code", snippet: "vars.http_status: status_code\n", description: "Recommended: destination-first." },
            { label: "vars.http_body: body", snippet: "vars.http_body: body\n", description: "Recommended: destination-first." },
            { label: "vars.http_headers: headers", snippet: "vars.http_headers: headers\n", description: "Recommended: destination-first." },
            { label: "vars.__CURSOR__: status_code", snippet: "vars.__CURSOR__: status_code\n", description: "Add a custom destination var." },

            // old style (still useful if you haven’t migrated yet)
            { label: "status_code: vars.http_status (legacy)", snippet: "status_code: vars.http_status\n", description: "Legacy format (source-first)." },
            { label: "body: vars.http_body (legacy)", snippet: "body: vars.http_body\n", description: "Legacy format (source-first)." },
            { label: "headers: vars.http_headers (legacy)", snippet: "headers: vars.http_headers\n", description: "Legacy format (source-first)." },
          ],
        };
      }

      // LEGACY: status_code/body/headers keys => suggest vars.* targets
      if (key === "status_code" || key === "body" || key === "headers") {
        return {
          groupTitle: "Vars targets",
          description: `Select target var for "${key}" (legacy format)`,
          action: "replace_value",
          values: captureTargetChoices(),
        };
      }

      // NEW: vars.* keys => suggest capture sources
      if (key.startsWith("vars.")) {
        return {
          groupTitle: "Capture sources",
          description: `Select source for "${key}" (recommended format)`,
          action: "replace_value",
          values: captureSourceChoices(),
        };
      }

      // Any other key is invalid in BOTH formats => guide the user
      return {
        groupTitle: "Capture",
        description: "Capture keys must be either status_code/body/headers (legacy) OR vars.* (recommended).",
        action: "insert_snippet",
        values: [
          { label: "Use recommended format", snippet: "vars.__CURSOR__: status_code\n", description: "Destination-first capture line." },
        ],
      };
    }

    // ---------------- WEBHOOK METHOD ----------------
    if (stepType === "webhook" && key === "method") {
      return {
        groupTitle: "Values",
        description: "HTTP method",
        action: "replace_value",
        values: [
          { label: "GET", value: "GET", description: "Fetch data (no side effects)." },
          { label: "POST", value: "POST", description: "Create / submit." },
          { label: "PUT", value: "PUT", description: "Replace a resource (idempotent)." },
          { label: "PATCH", value: "PATCH", description: "Partial update." },
          { label: "DELETE", value: "DELETE", description: "Delete a resource." },
        ],
      };
    }

    // ---------------- LOGIC ----------------
    if (stepType === "logic" && key === "op" && stack.includes("compare")) {
      return {
        groupTitle: "Operators",
        description: "Compare operator",
        action: "replace_value",
        values: [
          { label: "==", value: "==", description: "Equal" },
          { label: "!=", value: "!=", description: "Not equal" },
          { label: "<", value: "<", description: "Less than" },
          { label: "<=", value: "<=", description: "Less than or equal" },
          { label: ">", value: ">", description: "Greater than" },
          { label: ">=", value: ">=", description: "Greater than or equal" },
        ],
      };
    }

    if (stepType === "logic" && !key && stack.includes("when")) {
      return {
        groupTitle: "When operators",
        description: "Insert a condition operator",
        action: "insert_snippet",
        values: [
          {
            label: "compare",
            snippet:
              "compare:\n" +
              "  left: ${vars.__CURSOR__}\n" +
              "  op: \"==\"\n" +
              "  right: 0\n",
            description: "Compare left and right values with an operator.",
          },
          { label: "exists", snippet: "exists: ${vars.__CURSOR__}\n", description: "True if value exists / not null." },
          {
            label: "and",
            snippet:
              "and:\n" +
              "  - compare:\n" +
              "      left: ${vars.__CURSOR__}\n" +
              "      op: \"==\"\n" +
              "      right: 0\n" +
              "  - exists: ${event.device.id}\n",
            description: "All conditions must be true.",
          },
          {
            label: "or",
            snippet:
              "or:\n" +
              "  - compare:\n" +
              "      left: ${vars.__CURSOR__}\n" +
              "      op: \"==\"\n" +
              "      right: 0\n" +
              "  - exists: ${vars.foo}\n",
            description: "At least one condition must be true.",
          },
          { label: "not", snippet: "not:\n  exists: ${vars.__CURSOR__}\n", description: "Negate a condition." },
        ],
      };
    }

    // ---------------- COMPUTE (YAML op tree) ----------------
    if (stepType === "compute") {
      const targetCtx = detectComputeTargetContext(ctx, lines);
      if (targetCtx) {
        if (isListItemLine(line)) {
          return {
            groupTitle: "Vars",
            description: "Insert common variable references",
            action: "insert_snippet",
            values: [
              { label: "${vars.<name>}", snippet: "${vars.__CURSOR__}\n", description: "Reference a runtime variable." },
              { label: "${event.<path>}", snippet: "${event.__CURSOR__}\n", description: "Reference trigger event data." },
            ],
          };
        }

        if (isBlankOrComment(line) || (!key && !line.trim())) {
          return {
            groupTitle: "Operators",
            description: "Insert a compute operator (YAML op form)",
            action: "insert_snippet",
            values: [
              { label: "add", snippet: "add:\n  - ${vars.__CURSOR__}\n  - 1\n", description: "Addition: a + b" },
              { label: "sub", snippet: "sub:\n  - ${vars.__CURSOR__}\n  - 1\n", description: "Subtraction: a - b" },
              { label: "mul", snippet: "mul:\n  - ${vars.__CURSOR__}\n  - 2\n", description: "Multiplication" },
              { label: "div", snippet: "div:\n  - ${vars.__CURSOR__}\n  - 2\n", description: "Division" },
              { label: "min", snippet: "min:\n  - ${vars.__CURSOR__}\n  - 0\n", description: "Minimum of args" },
              { label: "max", snippet: "max:\n  - ${vars.__CURSOR__}\n  - 0\n", description: "Maximum of args" },
              { label: "round", snippet: "round:\n  - ${vars.__CURSOR__}\n", description: "Round a number" },
              { label: "int", snippet: "int:\n  - ${vars.__CURSOR__}\n", description: "Convert to integer" },
              { label: "float", snippet: "float:\n  - ${vars.__CURSOR__}\n", description: "Convert to float" },
            ],
          };
        }
      }
    }

    return null;
  };
})();