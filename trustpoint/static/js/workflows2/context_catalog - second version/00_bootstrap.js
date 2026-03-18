// static/js/workflows2/context_catalog/00_bootstrap.js
(function () {
  window.WF2CC = window.WF2CC || {};

  const WF2CC = window.WF2CC;

  WF2CC.config = WF2CC.config || {
    indent: "  ", // YAML = 2 spaces
  };

  // Optional internal namespaces (no bundler, so keep globals tidy)
  WF2CC.dom = WF2CC.dom || {};
  WF2CC.edit = WF2CC.edit || {};
  WF2CC.snippets = WF2CC.snippets || {};
  WF2CC.yaml = WF2CC.yaml || {};
  WF2CC.api = WF2CC.api || {};
  WF2CC.ui = WF2CC.ui || {};
})();
