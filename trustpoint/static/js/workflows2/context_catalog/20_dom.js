// static/js/workflows2/context_catalog/20_dom.js
(function () {
  const WF2CC = window.WF2CC;

  WF2CC.dom.getYamlTextarea = function getYamlTextarea() {
    return document.querySelector("textarea[name='yaml_text']") || document.querySelector("#id_yaml_text");
  };

  // Backwards-compatible alias
  WF2CC.getYamlTextarea = WF2CC.dom.getYamlTextarea;
})();
