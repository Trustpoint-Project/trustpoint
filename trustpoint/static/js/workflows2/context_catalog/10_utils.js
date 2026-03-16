// static/js/workflows2/context_catalog/10_utils.js
(function () {
  const WF2CC = window.WF2CC;

  WF2CC.esc = function esc(s) {
    return String(s).replace(/[&<>\"]/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
    }[c]));
  };

  WF2CC.debounce = function debounce(fn, ms) {
    let t = null;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  };

  WF2CC.safeReadText = async function safeReadText(resp) {
    try { return await resp.text(); } catch { return ""; }
  };
})();
