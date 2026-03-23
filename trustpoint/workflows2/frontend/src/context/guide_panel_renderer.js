import { text } from '../core/dom.js';
import { renderGuideContent } from './guide_content_renderer.js';

function getCurrentYamlFallback() {
  const textarea =
    document.querySelector('#id_yaml_text') ||
    document.querySelector('textarea[name="yaml_text"]');

  return textarea?.value || '';
}

export function renderCatalogSummary(catalog, els) {
  text(els.catalogVersionEl, `v${catalog?.meta?.version || '?'}`);
}

export function renderCurrentContext(context, catalog, els, yamlText = null) {
  const safeYamlText = yamlText == null ? getCurrentYamlFallback() : yamlText;
  els.guideContentEl.innerHTML = renderGuideContent(context, catalog, safeYamlText);
  text(els.currentPathEl, context?.pathLabel || '(root)');
}