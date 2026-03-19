import { text } from '../../core/dom.js';
import { renderGuideContent } from './guide_sections.js';

export function renderCatalogSummary(catalog, els) {
  text(els.catalogVersionEl, `v${catalog?.meta?.version || '?'}`);
}

export function renderCurrentContext(context, catalog, els) {
  els.guideContentEl.innerHTML = renderGuideContent(context, catalog);
  text(els.currentPathEl, context?.pathLabel || '(root)');
}