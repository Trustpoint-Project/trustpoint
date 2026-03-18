(function () {
  "use strict";

  function $(selector, root) {
    return (root || document).querySelector(selector);
  }

  function text(el, value) {
    if (el) el.textContent = value;
  }

  function escapeHtml(value) {
    return String(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  function renderChips(items, renderItem) {
    if (!Array.isArray(items) || !items.length) {
      return '<span class="text-muted">None</span>';
    }
    return items.map(renderItem).join("");
  }

  function lineColFromOffset(source, offset) {
    var idx = Math.max(0, Math.min(offset, source.length));
    var lines = source.slice(0, idx).split("\n");
    var line = lines.length;
    var col = lines[lines.length - 1].length + 1;
    return { line: line, col: col };
  }

  async function fetchJson(url) {
    var res = await fetch(url, {
      headers: {
        "X-Requested-With": "XMLHttpRequest"
      },
      credentials: "same-origin"
    });
    if (!res.ok) {
      throw new Error("HTTP " + res.status + " while loading " + url);
    }
    return await res.json();
  }

  async function postJson(url, payload) {
    var res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest"
      },
      credentials: "same-origin",
      body: JSON.stringify(payload)
    });

    var data;
    try {
      data = await res.json();
    } catch (err) {
      throw new Error("Invalid JSON response from " + url);
    }

    if (!res.ok) {
      throw new Error(data && data.error ? data.error : ("HTTP " + res.status));
    }

    return data;
  }

  function debounce(fn, wait) {
    var timer = null;
    return function () {
      var args = arguments;
      clearTimeout(timer);
      timer = setTimeout(function () {
        fn.apply(null, args);
      }, wait);
    };
  }

  function renderRuntimeRoots(meta) {
    var roots = (((meta || {}).template_runtime || {}).roots || []);
    var notes = (((meta || {}).template_runtime || {}).notes || []);

    var rootHtml = renderChips(roots, function (root) {
      return (
        '<span class="wf2-chip">' +
        "<strong>" + escapeHtml(root.title || root.key || "") + "</strong>" +
        " &middot; " + escapeHtml(root.key || "") +
        (root.dynamic ? " &middot; dynamic" : "") +
        "</span>"
      );
    });

    var noteHtml = "";
    if (notes.length) {
      noteHtml =
        '<div class="mt-2 text-muted">' +
        notes.map(function (n) {
          return '<div>&bull; ' + escapeHtml(n) + "</div>";
        }).join("") +
        "</div>";
    }

    return rootHtml + noteHtml;
  }

  function renderTriggerList(events) {
    return renderChips(events, function (evt) {
      return (
        '<span class="wf2-chip">' +
        "<strong>" + escapeHtml(evt.title || evt.key || "") + "</strong>" +
        " &middot; " + escapeHtml(evt.key || "") +
        "</span>"
      );
    });
  }

  function renderStepList(steps) {
    return renderChips(steps, function (step) {
      var required = Array.isArray(step.fields)
        ? step.fields.filter(function (f) { return !!f.required; }).length
        : 0;
      var optional = Array.isArray(step.fields)
        ? step.fields.filter(function (f) { return !f.required; }).length
        : 0;

      return (
        '<span class="wf2-chip">' +
        "<strong>" + escapeHtml(step.title || step.type || "") + "</strong>" +
        " &middot; " + escapeHtml(step.type || "") +
        " &middot; req " + required +
        " &middot; opt " + optional +
        "</span>"
      );
    });
  }

  async function init() {
    var root = $("#wf2-editor-root");
    if (!root) return;

    var textarea = $("#id_yaml_text") || $('textarea[name="yaml_text"]');
    var openVarsBtn = $("#wf2-open-vars");
    var formatBtn = $("#wf2-format-yaml");
    var statusEl = $("#wf2-editor-status");
    var cursorInfoEl = $("#wf2-cursor-info");
    var runtimeRootsEl = $("#wf2-runtime-roots");
    var triggerListEl = $("#wf2-trigger-list");
    var stepListEl = $("#wf2-step-list");
    var graphPreviewEl = $("#wf2-graph-preview");
    var graphStatusEl = $("#wf2-graph-status");
    var catalogVersionEl = $("#wf2-catalog-version");
    var contextCard = $("#wf2-context-card");

    if (!textarea) {
      text(statusEl, "YAML textarea not found.");
      return;
    }

    function updateCursorInfo() {
      var pos = lineColFromOffset(textarea.value || "", textarea.selectionStart || 0);
      text(cursorInfoEl, "Line " + pos.line + ", column " + pos.col);
    }

    textarea.addEventListener("click", updateCursorInfo);
    textarea.addEventListener("keyup", updateCursorInfo);
    textarea.addEventListener("input", updateCursorInfo);
    textarea.addEventListener("focus", updateCursorInfo);
    updateCursorInfo();

    if (openVarsBtn && contextCard) {
      openVarsBtn.addEventListener("click", function () {
        contextCard.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }

    if (formatBtn) {
      formatBtn.addEventListener("click", function () {
        text(
          statusEl,
          "Format YAML is intentionally disabled for this shell. It will be reconnected once the new YAML parser/editor layer is added."
        );
      });
    }

    try {
      var catalog = await fetchJson(root.dataset.contextCatalogUrl);
      text(catalogVersionEl, "Catalog v" + (((catalog || {}).meta || {}).version || "?"));
      runtimeRootsEl.innerHTML = renderRuntimeRoots((catalog || {}).meta || {});
      triggerListEl.innerHTML = renderTriggerList((catalog || {}).events || []);
      stepListEl.innerHTML = renderStepList((catalog || {}).steps || []);
      text(
        statusEl,
        "Shell loaded. Catalog connected. Live graph preview is active. Next step is replacing the textarea with the structured editor."
      );
    } catch (err) {
      runtimeRootsEl.innerHTML = '<span class="text-danger">Failed to load runtime roots.</span>';
      triggerListEl.innerHTML = '<span class="text-danger">Failed to load triggers.</span>';
      stepListEl.innerHTML = '<span class="text-danger">Failed to load step types.</span>';
      text(statusEl, "Catalog load failed: " + err.message);
    }

    var graphSeq = 0;

    async function refreshGraphPreview() {
      var yamlText = textarea.value || "";
      if (!yamlText.trim()) {
        text(graphStatusEl, "Empty");
        graphPreviewEl.textContent = "No YAML entered.";
        return;
      }

      var seq = ++graphSeq;
      text(graphStatusEl, "Updating…");

      try {
        var graph = await postJson(root.dataset.graphFromYamlUrl, {
          yaml_text: yamlText
        });

        if (seq !== graphSeq) return;

        text(graphStatusEl, "Live");
        graphPreviewEl.textContent = JSON.stringify(graph, null, 2);
      } catch (err) {
        if (seq !== graphSeq) return;

        text(graphStatusEl, "Error");
        graphPreviewEl.textContent =
          "Graph preview failed.\n\n" +
          err.message;
      }
    }

    var debouncedRefreshGraph = debounce(refreshGraphPreview, 450);
    textarea.addEventListener("input", debouncedRefreshGraph);

    await refreshGraphPreview();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();