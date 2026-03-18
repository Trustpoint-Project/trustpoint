// static/js/workflows2/context_catalog/42_format_api.js
(function () {
  const WF2CC = window.WF2CC;

  function getCookie(name) {
    const v = document.cookie ? document.cookie.split(";") : [];
    for (let i = 0; i < v.length; i += 1) {
      const c = v[i].trim();
      if (c.startsWith(name + "=")) return decodeURIComponent(c.slice(name.length + 1));
    }
    return "";
  }

  WF2CC.api.formatYaml = async function formatYaml(yamlText) {
    const url = window.WF2_FORMAT_YAML_URL;
    if (!url) throw new Error("WF2_FORMAT_YAML_URL is not set");

    const csrftoken = getCookie("csrftoken");

    const r = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRFToken": csrftoken,
      },
      body: JSON.stringify({ yaml: String(yamlText || "") }),
    });

    const body = await r.json().catch(async () => ({ ok: false, error: await WF2CC.safeReadText(r) }));
    if (!r.ok || !body || body.ok === false) {
      throw new Error(body && body.error ? body.error : `HTTP ${r.status} ${r.statusText}`);
    }
    return body.yaml;
  };
})();
