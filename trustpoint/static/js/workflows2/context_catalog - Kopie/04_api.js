// static/js/workflows2/context_catalog/04_api.js
(function () {
  const WF2CC = window.WF2CC;

  WF2CC.loadCatalog = async function loadCatalog() {
    const url = window.WF2_CONTEXT_CATALOG_URL || window.WF2_EVENT_CATALOG_URL;
    if (!url) return { events: [], steps: [], presets: [] };

    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) {
      const body = await WF2CC.safeReadText(r);
      throw new Error(`HTTP ${r.status} ${r.statusText}\n${body}`);
    }
    return await r.json();
  };
})();
