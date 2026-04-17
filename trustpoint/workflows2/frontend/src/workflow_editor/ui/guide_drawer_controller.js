export function createGuideDrawerController({
  drawerEl,
  openButton,
  closeButton,
}) {
  function open() {
    document.body.classList.add('wf2-guide-open');
    syncAria();
  }

  function close() {
    document.body.classList.remove('wf2-guide-open');
    syncAria();
  }

  function syncAria() {
    if (!drawerEl) {
      return;
    }

    drawerEl.setAttribute(
      'aria-hidden',
      document.body.classList.contains('wf2-guide-open') ? 'false' : 'true',
    );
  }

  if (openButton) {
    openButton.addEventListener('click', open);
  }

  if (closeButton) {
    closeButton.addEventListener('click', close);
  }

  document.addEventListener('keydown', (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
      event.preventDefault();
      open();
      return;
    }

    if (event.key === 'Escape' && document.body.classList.contains('wf2-guide-open')) {
      close();
    }
  });

  return {
    open,
    close,
    syncAria,
  };
}