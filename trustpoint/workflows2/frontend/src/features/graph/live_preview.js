import { debounce } from '../../core/utils.js';
import { postJson } from '../../core/http.js';
import { text } from '../../core/dom.js';

export function createLiveGraphPreview({ url, statusEl, previewEl, wait = 450 }) {
  let seq = 0;

  async function refresh(yamlText) {
    if (!yamlText.trim()) {
      text(statusEl, 'Empty');
      previewEl.textContent = 'No YAML entered.';
      return;
    }

    const currentSeq = ++seq;
    text(statusEl, 'Updating…');

    try {
      const graph = await postJson(url, { yaml_text: yamlText });

      if (currentSeq !== seq) {
        return;
      }

      text(statusEl, 'Live');
      previewEl.textContent = JSON.stringify(graph, null, 2);
    } catch (err) {
      if (currentSeq !== seq) {
        return;
      }

      text(statusEl, 'Error');
      previewEl.textContent =
        'Graph preview failed.\n\n' +
        (err instanceof Error ? err.message : String(err));
    }
  }

  return {
    refresh,
    debouncedRefresh: debounce(refresh, wait),
  };
}