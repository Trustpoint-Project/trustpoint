// static/js/workflows2/context_catalog/41_sources_api.js
(function () {
  const WF2CC = window.WF2CC;

  function normArr(x) {
    return Array.isArray(x) ? x : [];
  }

  function normalize(payload) {
    // Accept many shapes:
    // - {cas:[...], domains:[...], devices:[...]}
    // - {ok:true, sources:{...}}
    // - {ok:true, cas:[...], ...}
    const root = payload && payload.sources ? payload.sources : payload || {};

    return {
      cas: normArr(root.cas || root.issuing_cas || root.issuingCas || root.ca_list || root.cas_list),
      domains: normArr(root.domains || root.domain_list || root.domainList),
      devices: normArr(root.devices || root.device_list || root.deviceList),
    };
  }

  WF2CC.api = WF2CC.api || {};

  WF2CC.api.loadSources = async function loadSources() {
    const url = window.WF2_CONTEXT_SOURCES_URL;
    if (!url) return { cas: [], domains: [], devices: [] };

    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) {
      const body = await WF2CC.safeReadText(r);
      throw new Error(`HTTP ${r.status} ${r.statusText}\n${body}`);
    }

    const data = await r.json();

    if (data && data.ok === false) {
      throw new Error(String(data.error || "Failed to load sources."));
    }

    return normalize(data);
  };

  // Backwards-compatible alias
  WF2CC.loadSources = WF2CC.api.loadSources;
})();