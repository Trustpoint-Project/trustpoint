// static/js/workflows2/diagram_svg.js
(function () {
  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c]));
  }

  function wrapText(str, maxChars) {
    const s = String(str || "").trim();
    if (!s) return [""];
    const words = s.split(/\s+/);
    const lines = [];
    let cur = "";
    for (const w of words) {
      const next = cur ? (cur + " " + w) : w;
      if (next.length <= maxChars) cur = next;
      else {
        if (cur) lines.push(cur);
        cur = w;
      }
    }
    if (cur) lines.push(cur);
    return lines;
  }

  function rectsIntersect(a, b) {
    return !(
      (a.x + a.w) <= b.x ||
      (b.x + b.w) <= a.x ||
      (a.y + a.h) <= b.y ||
      (b.y + b.h) <= a.y
    );
  }

  function expandRect(r, pad) {
    return { x: r.x - pad, y: r.y - pad, w: r.w + pad * 2, h: r.h + pad * 2 };
  }

  function computeNodeBoxes(nodes) {
    const boxW = 220;
    const baseH = 56;
    const extraPerLine = 14;

    const boxes = new Map();
    nodes.forEach((n) => {
      const titleRaw = n.title ? String(n.title) : String(n.id || "");
      const lines = wrapText(titleRaw, 24).slice(0, 2);
      const extra = (lines.length > 1) ? extraPerLine : 0;
      const h = baseH + extra;
      boxes.set(n.id, { w: boxW, h, titleLines: lines });
    });
    return boxes;
  }

  function layout(graph) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    const byId = new Map(nodes.map((n) => [n.id, n]));
    const outgoing = new Map();
    nodes.forEach((n) => outgoing.set(n.id, []));

    edges.forEach((e) => {
      if (!outgoing.has(e.from)) outgoing.set(e.from, []);
      outgoing.get(e.from).push(e);
    });

    const start = (graph.start && byId.has(graph.start)) ? graph.start : (nodes[0]?.id || null);
    const level = new Map();
    if (start) level.set(start, 0);

    const q = start ? [start] : [];
    while (q.length) {
      const cur = q.shift();
      const l = level.get(cur) || 0;
      (outgoing.get(cur) || []).forEach((e) => {
        if (!level.has(e.to)) {
          level.set(e.to, l + 1);
          q.push(e.to);
        }
      });
    }

    const groups = new Map();
    nodes.forEach((n) => {
      const l = level.has(n.id) ? level.get(n.id) : 999;
      if (!groups.has(l)) groups.set(l, []);
      groups.get(l).push(n.id);
    });
    [...groups.keys()].sort((a, b) => a - b).forEach((k) => groups.get(k).sort());

    const boxes = computeNodeBoxes(nodes);
    const pos = new Map();

    const colWidth = 320;
    const padX = 40;
    const padY = 30;
    const rowGap = 24;

    let maxX = 0;
    let maxY = 0;

    [...groups.keys()].sort((a, b) => a - b).forEach((l) => {
      const ids = groups.get(l);
      let y = padY;

      ids.forEach((id) => {
        const x = padX + l * colWidth;
        pos.set(id, { x, y });

        const b = boxes.get(id) || { w: 220, h: 56 };
        maxX = Math.max(maxX, x + b.w);
        maxY = Math.max(maxY, y + b.h);

        y += b.h + rowGap;
      });
    });

    const nodeRects = new Map();
    nodes.forEach((n) => {
      const p = pos.get(n.id);
      const b = boxes.get(n.id);
      if (!p || !b) return;
      nodeRects.set(n.id, { x: p.x, y: p.y, w: b.w, h: b.h });
    });

    return { pos, boxes, nodeRects, width: maxX + 80, height: maxY + 80 };
  }

  function groupEdgesByFrom(edges) {
    const map = new Map();
    edges.forEach((e) => {
      const k = String(e.from || "");
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(e);
    });
    for (const [k, arr] of map.entries()) {
      arr.sort((a, b) => {
        const ao = String(a.on ?? "");
        const bo = String(b.on ?? "");
        const c = ao.localeCompare(bo);
        if (c !== 0) return c;
        return String(a.to || "").localeCompare(String(b.to || ""));
      });
      map.set(k, arr);
    }
    return map;
  }

  function groupEdgesByTo(edges) {
    const map = new Map();
    edges.forEach((e) => {
      const k = String(e.to || "");
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(e);
    });
    for (const [k, arr] of map.entries()) {
      arr.sort((a, b) => String(a.from || "").localeCompare(String(b.from || "")));
      map.set(k, arr);
    }
    return map;
  }

  function tryNudgeYUntilFree(y, labelRectFn, nodeRects, placedLabelRects, avoidNodeIds) {
    const maxTries = 30;
    const step = 10;

    function collides(r) {
      for (const [id, nr] of nodeRects.entries()) {
        if (avoidNodeIds && avoidNodeIds.has(id)) continue;
        if (rectsIntersect(r, expandRect(nr, 6))) return true;
      }
      for (const lr of placedLabelRects) {
        if (rectsIntersect(r, expandRect(lr, 4))) return true;
      }
      return false;
    }

    for (let i = 0; i < maxTries; i++) {
      const dy = (i === 0) ? 0 : (Math.ceil(i / 2) * step) * (i % 2 === 1 ? 1 : -1);
      const yy = y + dy;
      const rect = labelRectFn(yy);
      if (!collides(rect)) return { y: yy, rect };
    }
    return { y, rect: labelRectFn(y) };
  }

  function estimateLabelRectAt(x, y, text) {
    const label = String(text || "");
    const approxCharW = 6.8;
    const w = Math.max(14, Math.min(260, Math.round(label.length * approxCharW)));
    const h = 16;
    return { x: x - w / 2, y: y - h / 2, w, h };
  }

  function edgeId(e) {
    // Stable string ID for pairing path <-> label
    const on = (e.on == null) ? "" : String(e.on);
    return `${String(e.from)}::${String(e.to)}::${on}`;
  }

  function renderToBox(box, graph) {
    const { pos, boxes, nodeRects, width, height } = layout(graph);
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];

    const byFrom = groupEdgesByFrom(edges);
    const byTo = groupEdgesByTo(edges);

    // Ports for fan-out
    const sourcePortY = new Map(); // edge -> y
    for (const [from, arr] of byFrom.entries()) {
      const p = pos.get(from);
      const b = boxes.get(from);
      if (!p || !b) continue;
      const cy = p.y + b.h / 2;

      const gap = 14;
      const m = arr.length;
      arr.forEach((e, idx) => {
        const off = (idx - (m - 1) / 2) * gap;
        sourcePortY.set(e, cy + off);
      });
    }

    // Ports for fan-in
    const targetPortY = new Map();
    for (const [to, arr] of byTo.entries()) {
      const p = pos.get(to);
      const b = boxes.get(to);
      if (!p || !b) continue;
      const cy = p.y + b.h / 2;

      const gap = 12;
      const m = arr.length;
      arr.forEach((e, idx) => {
        const off = (idx - (m - 1) / 2) * gap;
        targetPortY.set(e, cy + off);
      });
    }

    // Label lane right after source node
    const labelLaneX = new Map(); // from -> x
    for (const n of nodes) {
      const p = pos.get(n.id);
      const b = boxes.get(n.id);
      if (!p || !b) continue;
      labelLaneX.set(n.id, p.x + b.w + 54);
    }

    const placedLabelRects = [];

    const svgParts = [];
    svgParts.push(`<svg class="wf2-svg" width="100%" height="100%" viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg">`);

    // Styles inside the SVG so hover works everywhere
    svgParts.push(`
      <style>
        .wf2-edge-path { stroke: #000; stroke-width: 1.2; fill: none; }
        .wf2-edge-leader { stroke: #000; stroke-width: 1; opacity: .35; fill: none; stroke-dasharray: 3 3; }
        .wf2-edge-dot { fill: #000; opacity: .35; }
        .wf2-edge-label { font-size: 11px; text-anchor: middle; }
        .wf2-halo { stroke: #fff; stroke-width: 5; stroke-linejoin: round; paint-order: stroke; }
        .wf2-active .wf2-edge-path { stroke-width: 2.6; }
        .wf2-active .wf2-edge-leader { opacity: .75; stroke-width: 1.2; }
        .wf2-active .wf2-edge-dot { opacity: .75; }
      </style>
    `);

    // ---- edges (paths) ----
    edges.forEach((e) => {
      const a = pos.get(e.from);
      const bpos = pos.get(e.to);
      if (!a || !bpos) return;

      const ba = boxes.get(e.from) || { w: 220, h: 56 };
      const bb = boxes.get(e.to) || { w: 220, h: 56 };

      const x1 = a.x + ba.w;
      const y1 = sourcePortY.get(e) ?? (a.y + ba.h / 2);

      const x2 = bpos.x;
      const y2 = targetPortY.get(e) ?? (bpos.y + bb.h / 2);

      const midX = (x1 + x2) / 2;

      const eid = edgeId(e);

      svgParts.push(
        `<g class="wf2-edge" data-eid="${esc(eid)}">
          <path class="wf2-edge-path" d="M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}"/>
        </g>`
      );
    });

    // ---- nodes ----
    nodes.forEach((n) => {
      const p = pos.get(n.id);
      if (!p) return;

      const titleRaw = n.title ? String(n.title) : String(n.id || "");
      const subtitle = String(n.type || "");
      const b = boxes.get(n.id) || { w: 220, h: 56, titleLines: wrapText(titleRaw, 24).slice(0, 2) };
      const titleLines = b.titleLines || wrapText(titleRaw, 24).slice(0, 2);

      const subtitleY = (titleLines.length > 1) ? (p.y + 52) : (p.y + 40);

      svgParts.push(`<g>
        <rect x="${p.x}" y="${p.y}" rx="10" ry="10" width="${b.w}" height="${b.h}" fill="white" stroke="black"/>
        <text x="${p.x + 10}" y="${p.y + 20}" font-size="12" font-weight="600">
          ${titleLines.map((ln, i) => `<tspan x="${p.x + 10}" dy="${i === 0 ? 0 : 14}">${esc(ln)}</tspan>`).join("")}
        </text>
        <text x="${p.x + 10}" y="${subtitleY}" font-size="11" opacity="0.8">${esc(subtitle)}</text>
      </g>`);
    });

    // ---- labels + leaders ----
    edges.forEach((e) => {
      if (!e.on) return;

      const from = String(e.from || "");
      const to = String(e.to || "");
      const a = pos.get(from);
      const bpos = pos.get(to);
      if (!a || !bpos) return;

      const ba = boxes.get(from) || { w: 220, h: 56 };
      const bb = boxes.get(to) || { w: 220, h: 56 };

      const x1 = a.x + ba.w;
      const y1 = sourcePortY.get(e) ?? (a.y + ba.h / 2);

      const x2 = bpos.x;
      const y2 = targetPortY.get(e) ?? (bpos.y + bb.h / 2);

      // Where the curve starts to separate: a small anchor point near the source
      const anchorX = x1 + 18;
      const anchorY = y1;

      const labelX = labelLaneX.get(from) ?? (a.x + ba.w + 54);
      const baseY = y1;

      const label = String(e.on);
      const avoidNodeIds = new Set([from]);

      const result = tryNudgeYUntilFree(
        baseY,
        (yy) => estimateLabelRectAt(labelX, yy, label),
        nodeRects,
        placedLabelRects,
        avoidNodeIds
      );

      placedLabelRects.push(result.rect);

      const eid = edgeId(e);

      // Leader: from anchor to label (slight bend looks nicer)
      const leaderMidX = (anchorX + labelX) / 2;

      svgParts.push(`
        <g class="wf2-edge wf2-edge-labelwrap" data-eid="${esc(eid)}">
          <path class="wf2-edge-leader" d="M ${anchorX} ${anchorY} C ${leaderMidX} ${anchorY}, ${leaderMidX} ${result.y}, ${labelX} ${result.y}"/>
          <circle class="wf2-edge-dot" cx="${anchorX}" cy="${anchorY}" r="2.2"/>
          <text class="wf2-edge-label wf2-halo" x="${labelX}" y="${result.y + 4}">${esc(label)}</text>
          <text class="wf2-edge-label" x="${labelX}" y="${result.y + 4}" fill="#111">${esc(label)}</text>
        </g>
      `);
    });

    svgParts.push(`</svg>`);
    box.innerHTML = svgParts.join("");

    // ---- hover linking (edge <-> label) ----
    const svg = box.querySelector("svg.wf2-svg");
    if (!svg) return;

    const groups = Array.from(svg.querySelectorAll("g.wf2-edge[data-eid]"));
    const byEid = new Map();
    for (const g of groups) {
      const eid = g.getAttribute("data-eid");
      if (!eid) continue;
      if (!byEid.has(eid)) byEid.set(eid, []);
      byEid.get(eid).push(g);
    }

    function setActive(eid, on) {
      const arr = byEid.get(eid) || [];
      for (const g of arr) g.classList.toggle("wf2-active", !!on);
    }

    for (const [eid, arr] of byEid.entries()) {
      for (const g of arr) {
        g.addEventListener("mouseenter", () => setActive(eid, true));
        g.addEventListener("mouseleave", () => setActive(eid, false));
      }
    }
  }

  function ensureModal() {
    let modal = document.getElementById("wf2-graph-modal");
    if (modal) return modal;

    modal = document.createElement("div");
    modal.id = "wf2-graph-modal";
    modal.style.cssText = `
      position: fixed; inset: 0;
      background: rgba(0,0,0,.55);
      z-index: 2000;
      display: none;
      padding: 18px;
    `;

    modal.innerHTML = `
      <div style="
        background: #fff;
        border-radius: 10px;
        width: 100%;
        height: 100%;
        display: flex;
        flex-direction: column;
        overflow: hidden;
      ">
        <div style="
          padding: 10px 12px;
          border-bottom: 1px solid #eee;
          display: flex;
          align-items: center;
          justify-content: space-between;
          gap: 12px;
        ">
          <div style="font-weight: 600;">Flow (expanded)</div>
          <div style="display:flex; gap:8px; align-items:center;">
            <button type="button" class="btn btn-sm btn-outline-secondary" id="wf2-graph-modal-refresh">Refresh</button>
            <button type="button" class="btn btn-sm btn-outline-secondary" id="wf2-graph-modal-close">Close</button>
          </div>
        </div>
        <div id="wf2-graph-modal-canvas" style="flex: 1 1 auto; overflow: auto; background:#fff;"></div>
      </div>
    `;

    document.body.appendChild(modal);

    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.style.display = "none";
    });
    modal.querySelector("#wf2-graph-modal-close").addEventListener("click", () => {
      modal.style.display = "none";
    });

    return modal;
  }

  async function safeReadText(resp) {
    try { return await resp.text(); } catch { return ""; }
  }

  async function fetchJsonOrThrow(url, options) {
    const r = await fetch(url, options || { credentials: "same-origin" });
    if (!r.ok) {
      const body = await safeReadText(r);
      throw new Error(`HTTP ${r.status} ${r.statusText}\n${body.slice(0, 1200)}`);
    }
    const txt = await r.text();
    try {
      return JSON.parse(txt);
    } catch {
      throw new Error(`Invalid JSON from ${url}\n${txt.slice(0, 1200)}`);
    }
  }

  function getYamlTextarea() {
    return document.querySelector("textarea[name='yaml_text']") ||
           document.querySelector("#id_yaml_text");
  }

  function debounce(fn, ms) {
    let t = null;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }

  function showError(box, err) {
    const msg = (err && err.stack) ? err.stack : String(err);
    box.innerHTML = `<div class="text-danger p-3" style="white-space:pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;">${esc(msg)}</div>`;
  }

  async function loadGraph(box) {
    const graphUrl = box.dataset.graphUrl;
    const yamlUrl = window.WF2_GRAPH_FROM_YAML_URL;
    const yamlEl = getYamlTextarea();

    if (yamlUrl && yamlEl) {
      return await fetchJsonOrThrow(yamlUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ yaml_text: yamlEl.value || "" }),
      });
    }

    if (!graphUrl) {
      throw new Error("Missing data-graph-url on #wf2-diagram and WF2_GRAPH_FROM_YAML_URL not configured.");
    }

    return await fetchJsonOrThrow(graphUrl, { credentials: "same-origin" });
  }

  async function init() {
    const box = document.getElementById("wf2-diagram");
    if (!box) return;

    box.innerHTML = `<div class="text-muted p-3">Loading graph…</div>`;

    let lastGraph = null;

    async function renderNow(targetBox) {
      try {
        const graph = await loadGraph(box);
        lastGraph = graph;
        renderToBox(targetBox, graph);
      } catch (err) {
        showError(targetBox, err);
      }
    }

    await renderNow(box);

    const expandBtn = document.getElementById("wf2-expand-graph");
    if (expandBtn) {
      expandBtn.addEventListener("click", async () => {
        const modal = ensureModal();
        const canvas = modal.querySelector("#wf2-graph-modal-canvas");
        canvas.innerHTML = `<div class="text-muted p-3">Loading…</div>`;
        modal.style.display = "block";

        if (lastGraph) renderToBox(canvas, lastGraph);
        else await renderNow(canvas);

        const refreshBtn = modal.querySelector("#wf2-graph-modal-refresh");
        if (refreshBtn) {
          refreshBtn.onclick = async () => {
            canvas.innerHTML = `<div class="text-muted p-3">Loading…</div>`;
            await renderNow(canvas);
          };
        }
      });
    }

    if (window.WF2_GRAPH_FROM_YAML_URL) {
      const yamlEl = getYamlTextarea();
      if (yamlEl) {
        yamlEl.addEventListener("input", debounce(async () => {
          await renderNow(box);
        }, 250));
      }
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
