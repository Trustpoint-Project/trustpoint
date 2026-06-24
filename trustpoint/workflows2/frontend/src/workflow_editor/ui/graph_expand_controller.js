export function createGraphExpandController({
  cardEl,
  toggleButton,
}) {
  function applyButtonState(expanded) {
    if (!toggleButton) {
      return;
    }

    toggleButton.textContent = expanded ? 'Collapse' : 'Expand';
    toggleButton.setAttribute('aria-expanded', expanded ? 'true' : 'false');
  }

  function isExpanded() {
    return !!cardEl && cardEl.classList.contains('wf2-graph-expanded');
  }

  function expand() {
    if (!cardEl) {
      return;
    }

    cardEl.classList.add('wf2-graph-expanded');
    document.body.classList.add('wf2-graph-expanded');
    applyButtonState(true);
  }

  function collapse() {
    if (!cardEl) {
      return;
    }

    cardEl.classList.remove('wf2-graph-expanded');
    document.body.classList.remove('wf2-graph-expanded');
    applyButtonState(false);
  }

  function toggle() {
    if (isExpanded()) {
      collapse();
    } else {
      expand();
    }
  }

  if (toggleButton) {
    toggleButton.addEventListener('click', toggle);
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && isExpanded()) {
      collapse();
    }
  });

  applyButtonState(isExpanded());

  return {
    expand,
    collapse,
    toggle,
    isExpanded,
  };
}