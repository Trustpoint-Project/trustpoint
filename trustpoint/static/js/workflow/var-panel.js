// static/js/workflow/var-panel.js
import { buildDesignTimeCatalog } from './ui-context.js';
import { insertIntoActive } from './template-fields.js';

export class VarPanel {
  constructor({ getState }) {
    this.getState = getState;
    this.root = null;
    this.searchEl = null;
    this.listEl = null;
    this.isOpen = false;
    this._boundOnWFChange = () => this._renderList();
  }

  mount() {
    if (this.root) return;
    this._injectStyles();

    const panel = document.createElement('div');
    panel.className = 'vp-root vp-hidden';
    panel.innerHTML = `
      <div class="vp-header">
        <div class="vp-title">Variables</div>
        <button type="button" class="btn btn-sm btn-outline-light vp-close">×</button>
      </div>
      <div class="vp-body">
        <input type="search" class="form-control form-control-sm vp-search" placeholder="Search variable (e.g. step_2 status)" />
        <div class="vp-list" role="list"></div>
      </div>
      <div class="vp-footer small text-muted">
        Tip: focus a field, then click <strong>Insert</strong>. Press <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>K</kbd> to toggle.
      </div>
    `;
    document.body.appendChild(panel);

    this.root = panel;
    this.searchEl = panel.querySelector('.vp-search');
    this.listEl = panel.querySelector('.vp-list');

    panel.querySelector('.vp-close').onclick = () => this.close();
    this.searchEl.addEventListener('input', () => this._renderList());

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        this.toggle();
      }
    });

    // Listen for global workflow changes (emitted from main.js)
    document.addEventListener('wf:changed', this._boundOnWFChange);

    this._renderList();
  }

  destroy() {
    document.removeEventListener('wf:changed', this._boundOnWFChange);
    this.root?.remove();
    this.root = null;
  }

  open()  { this.isOpen = true;  this.root.classList.remove('vp-hidden'); this._renderList(); }
  close() { this.isOpen = false; this.root.classList.add('vp-hidden'); }
  toggle(){ this.isOpen ? this.close() : this.open(); }

  _renderList() {
    if (!this.listEl) return;

    const state = (typeof this.getState === 'function') ? this.getState() : { steps: [] };
    const catalog = buildDesignTimeCatalog({ state }) || { groups: [] };

    const q = (this.searchEl?.value || '').trim().toLowerCase();
    const frag = document.createDocumentFragment();

    for (const g of (catalog.groups || [])) {
      const header = document.createElement('div');
      header.className = 'vp-group';
      header.textContent = g.label || g.key;
      frag.appendChild(header);

      for (const v of (g.vars || [])) {
        const key = String(v.key || '');
        const label = String(v.label || key);
        const path = `ctx.${key}`;
        if (q && !(label.toLowerCase().includes(q) || key.toLowerCase().includes(q))) continue;

        const row = document.createElement('div');
        row.className = 'vp-item';
        row.innerHTML = `
          <div class="vp-item-text">
            <div class="vp-item-title">${this._esc(label)}</div>
            <div class="vp-item-sub">${this._esc(path)}</div>
          </div>
          <div class="vp-item-actions">
            <button type="button" class="btn btn-sm btn-primary">Insert</button>
            <button type="button" class="btn btn-sm btn-outline-secondary">Copy</button>
          </div>
        `;
        const [insertBtn, copyBtn] = row.querySelectorAll('.btn');
        insertBtn.onclick = () => {
          const ok = insertIntoActive(`{{ ${path} }}`);
          if (!ok) this._toast('Focus a field first.');
        };
        copyBtn.onclick = async () => {
          try { await navigator.clipboard.writeText(`{{ ${path} }}`); this._toast('Copied!'); }
          catch { this._toast('Copy failed.'); }
        };
        frag.appendChild(row);
      }
    }

    this.listEl.innerHTML = '';
    this.listEl.appendChild(frag);
  }

  _toast(msg) {
    if (!this.root) return;
    let t = this.root.querySelector('.vp-toast');
    if (!t) {
      t = document.createElement('div');
      t.className = 'vp-toast';
      this.root.appendChild(t);
    }
    t.textContent = msg;
    t.classList.add('show');
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => t.classList.remove('show'), 1100);
  }

  _esc(s) { return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

  _injectStyles() {
    if (document.getElementById('vp-styles')) return;
    const css = document.createElement('style');
    css.id = 'vp-styles';
    css.textContent = `
      .vp-root{ position:fixed; top:0; right:0; width:360px; max-width:90vw; height:100%;
        background: var(--bs-body-bg,#111); color: var(--bs-body-color,#eee);
        border-left:1px solid var(--bs-border-color,#333); box-shadow:-6px 0 16px rgba(0,0,0,.25);
        z-index:1050; display:flex; flex-direction:column; }
      .vp-hidden{ display:none; }
      .vp-header{ display:flex; align-items:center; justify-content:space-between; padding:.5rem .75rem;
        border-bottom:1px solid var(--bs-border-color,#333); }
      .vp-title{ font-weight:600; }
      .vp-body{ padding:.5rem; display:flex; flex-direction:column; gap:.5rem; overflow:hidden; }
      .vp-search{ flex:0 0 auto; }
      .vp-list{ flex:1 1 auto; overflow:auto; padding-bottom:2.5rem; }
      .vp-group{ font-size:.75rem; letter-spacing:.02em; color: var(--bs-secondary-color,#aaa);
        text-transform:uppercase; margin:.6rem .25rem .35rem; }
      .vp-item{ display:flex; align-items:center; justify-content:space-between; gap:.5rem;
        padding:.5rem; border:1px solid var(--bs-border-color,#333); border-radius:.5rem;
        background: var(--bs-tertiary-bg, rgba(255,255,255,.02)); margin-bottom:.5rem; }
      .vp-item-text{ min-width:0; }
      .vp-item-title{ font-weight:600; margin-bottom:.15rem; }
      .vp-item-sub{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
        font-size:.8rem; color: var(--bs-secondary-color,#bbb); word-break: break-all; }
      .vp-item-actions{ display:flex; align-items:center; gap:.4rem; flex:0 0 auto; }
      .vp-footer{ padding:.4rem .6rem; border-top:1px solid var(--bs-border-color,#333); }
      .vp-toast{ position:absolute; bottom:.6rem; left:50%; transform:translateX(-50%);
        background: rgba(0,0,0,.8); color:#fff; padding:.35rem .6rem; border-radius:.4rem;
        font-size:.8rem; opacity:0; transition:opacity .15s ease; pointer-events:none; }
      .vp-toast.show{ opacity:1; }
    `;
    document.head.appendChild(css);
  }
}
