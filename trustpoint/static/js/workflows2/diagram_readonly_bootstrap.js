document.addEventListener('DOMContentLoaded', () => {
  const canvas = document.getElementById('wf2-canvas');
  const graphUrl = canvas?.dataset?.graphUrl || '';
  if (graphUrl) {
    window.WF2_GRAPH_URL = graphUrl;
  }
});
