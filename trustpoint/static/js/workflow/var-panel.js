// static/js/workflow/var-panel.js
import { buildDesignTimeCatalog } from './ui-context.js';
import { insertIntoActive } from './template-fields.js';

export class VarPanel {
  constructor({ getState }) {
    this.getState = getState;

    this.root = null;
    this.searchEl = null;

    this.treeEl = null;
    this.resultsEl = null;

    this.isOpen = false;
    this._toastTimer = null;

    this._selectedGroupKey = null;
    this._selectedVarKey = null;
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
        <input type="search" class="form-control form-control-sm vp-search"
               placeholder="Search variable (e.g. csr_pem, step_2.status, device.serial_number)" />

        <div class="vp-split">
          <div class="vp-tree" role="tree" aria-label="Variable groups"></div>
          <div class="vp-results" role="list" aria-label="Variables"></div>
        </div>
      </div>

      <div class="vp-footer small text-muted">
        Tip: focus a field, then click <strong>Insert</strong>. Press <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>K</kbd> to toggle.
      </div>
    `;
    document.body.appendChild(panel);

    this.root = panel;
    this.searchEl = panel.querySelector('.vp-search');
    this.treeEl = panel.querySelector('.vp-tree');
    this.resultsEl = panel.querySelector('.vp-results');

    panel.querySelector('.vp-close').onclick = () => this.close();
    this.searchEl.addEventListener('input', () => this._render());

    window.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        this.toggle();
      }
      if (this.isOpen && e.key === 'Escape') {
        e.preventDefault();
        this.close();
      }
    });

    // Auto-refresh when the wizard state changes
    document.addEventListener('wf:changed', () => this._render());

    this._render();
  }

  open() {
    this.isOpen = true;
    this.root.classList.remove('vp-hidden');
    document.body.classList.add('vp-open');
    this._render();
    this.searchEl?.focus();
  }

  close() {
    this.isOpen = false;
    this.root.classList.add('vp-hidden');
    document.body.classList.remove('vp-open');
  }

  toggle() {
    this.isOpen ? this.close() : this.open();
  }

  refresh() {
    this._render();
  }

  _render() {
    if (!this.treeEl || !this.resultsEl) return;

    const state = (typeof this.getState === 'function') ? this.getState() : { steps: [] };
    const catalog = buildDesignTimeCatalog({ state }) || { groups: [] };

    const groups = this._normalizeGroups(catalog.groups || []);
    if (!this._selectedGroupKey && groups.length) this._selectedGroupKey = groups[0].key;

    this._renderTree(groups);
    this._renderResults(groups);
  }

  _normalizeGroups(groups) {
    // Accept both:
    //  - { key,label, vars:[{key,label}] } (your current design-time)
    //  - { name, vars:[{path,label}] } (backend future)
    return groups.map((g, gi) => {
      const key = String(g.key || g.name || `group_${gi}`);
      const label = String(g.label || g.name || key);

      const vars = (g.vars || []).map((v, vi) => {
        // design-time uses v.key; backend uses v.path
        const rawKey = v.key || v.path || '';
        // We want to show/insert full ctx path:
        // - design-time v.key is like "device.common_name" -> ctx.device.common_name
        // - backend v.path is already "ctx.device.common_name"
        const ctxPath = String(rawKey).startsWith('ctx.')
          ? String(rawKey)
          : `ctx.${String(rawKey)}`;

        return {
          key: String(v.key || v.path || `var_${gi}_${vi}`),
          label: String(v.label || v.key || v.path || ctxPath),
          ctxPath,
        };
      });

      return { key, label, vars };
    });
  }

  _renderTree(groups) {
    const frag = document.createDocumentFragment();

    // “All” pseudo group
    frag.appendChild(this._treeNode({
      key: '__all__',
      label: 'All',
      count: groups.reduce((n, g) => n + (g.vars?.length || 0), 0),
      selected: this._selectedGroupKey === '__all__',
      onClick: () => {
        this._selectedGroupKey = '__all__';
        this._selectedVarKey = null;
        this._render();
      },
    }));

    // Real groups (collapsible)
    for (const g of groups) {
      const details = document.createElement('details');
      details.className = 'vp-tree-group';
      details.open = (this._selectedGroupKey === g.key);

      const summary = document.createElement('summary');
      summary.className = 'vp-tree-group-title';
      summary.innerHTML = `
        <span class="vp-tree-group-label">${this._esc(g.label)}</span>
        <span class="vp-tree-count">${g.vars.length}</span>
      `;
      summary.onclick = (e) => {
        // Select group on summary click without toggling twice.
        e.preventDefault();
        details.open = !details.open;
        this._selectedGroupKey = g.key;
        this._selectedVarKey = null;
        this._render();
      };
      details.appendChild(summary);

      const list = document.createElement('div');
      list.className = 'vp-tree-items';
      for (const v of g.vars) {
        const node = this._treeNode({
          key: v.key,
          label: v.label,
          mono: v.ctxPath,
          selected: this._selectedVarKey === v.key,
          onClick: () => {
            this._selectedGroupKey = g.key;
            this._selectedVarKey = v.key;
            // also populate search with the path segment for convenience? no.
            this._render();
          },
        });
        list.appendChild(node);
      }
      details.appendChild(list);
      frag.appendChild(details);
    }

    this.treeEl.innerHTML = '';
    this.treeEl.appendChild(frag);
  }

  _treeNode({ key, label, mono = null, count = null, selected = false, onClick }) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `vp-tree-node${selected ? ' is-selected' : ''}`;
    btn.dataset.key = key;
    btn.innerHTML = `
      <div class="vp-tree-node-main">
        <span class="vp-tree-node-label">${this._esc(label)}</span>
        ${count != null ? `<span class="vp-tree-count">${count}</span>` : ''}
      </div>
      ${mono ? `<div class="vp-tree-node-mono">${this._esc(mono)}</div>` : ''}
    `;
    btn.onclick = onClick;
    return btn;
  }

  _renderResults(groups) {
    const q = (this.searchEl?.value || '').trim().toLowerCase();

    let visibleVars = [];

    if (q) {
      // Global search across all variables
      for (const g of groups) {
        for (const v of g.vars) {
          const key = String(v.key || '');
          const label = String(v.label || '');
          const path = String(v.ctxPath || '');
          if (
            label.toLowerCase().includes(q) ||
            key.toLowerCase().includes(q) ||
            path.toLowerCase().includes(q)
          ) {
            visibleVars.push({ groupLabel: g.label, ...v });
          }
        }
      }
      // stable grouping in results: group name + label sort
      visibleVars.sort((a, b) => {
        const g = a.groupLabel.localeCompare(b.groupLabel);
        if (g !== 0) return g;
        return String(a.label).localeCompare(String(b.label));
      });
    } else {
      // Show selected group (or all)
      if (this._selectedGroupKey === '__all__') {
        for (const g of groups) for (const v of g.vars) visibleVars.push({ groupLabel: g.label, ...v });
      } else {
        const g = groups.find(x => x.key === this._selectedGroupKey) || groups[0];
        if (g) visibleVars = g.vars.map(v => ({ groupLabel: g.label, ...v }));
      }
    }

    const frag = document.createDocumentFragment();

    if (q) {
      const head = document.createElement('div');
      head.className = 'vp-results-head';
      head.textContent = `Matches: ${visibleVars.length}`;
      frag.appendChild(head);
    }

    let lastGroup = null;
    for (const v of visibleVars) {
      if (q && v.groupLabel !== lastGroup) {
        lastGroup = v.groupLabel;
        const gh = document.createElement('div');
        gh.className = 'vp-group';
        gh.textContent = v.groupLabel;
        frag.appendChild(gh);
      }

      const row = document.createElement('div');
      row.className = 'vp-item';
      row.innerHTML = `
        <div class="vp-item-text">
          <div class="vp-item-title">${this._esc(v.label)}</div>
          <div class="vp-item-sub">${this._esc(v.ctxPath)}</div>
        </div>
        <div class="vp-item-actions">
          <button type="button" class="btn btn-sm btn-primary">Insert</button>
          <button type="button" class="btn btn-sm btn-outline-secondary">Copy</button>
        </div>
      `;

      const [insertBtn, copyBtn] = row.querySelectorAll('.btn');

      insertBtn.onclick = () => {
        const ok = insertIntoActive(`{{ ${v.ctxPath} }}`);
        if (!ok) this._toast('Focus a field first.');
      };

      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(`{{ ${v.ctxPath} }}`);
          this._toast('Copied!');
        } catch {
          this._toast('Copy failed.');
        }
      };

      frag.appendChild(row);
    }

    if (visibleVars.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'vp-empty text-muted small';
      empty.textContent = q ? 'No matches.' : 'No variables available.';
      frag.appendChild(empty);
    }

    this.resultsEl.innerHTML = '';
    this.resultsEl.appendChild(frag);
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

  _esc(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
  }

  _injectStyles() {
    if (document.getElementById('vp-styles')) return;
    const css = document.createElement('style');
    css.id = 'vp-styles';
    css.textContent = `
      .vp-root{
        position:fixed; top:0; right:0;
        width: 560px; max-width: 96vw; height:100%;
        background: var(--bs-body-bg,#111);
        color: var(--bs-body-color,#eee);
        border-left:1px solid var(--bs-border-color,#333);
        box-shadow:-6px 0 16px rgba(0,0,0,.25);
        z-index:1050; display:flex; flex-direction:column;
      }
      .vp-hidden{ display:none; }
      .vp-header{
        display:flex; align-items:center; justify-content:space-between;
        padding:.5rem .75rem; border-bottom:1px solid var(--bs-border-color,#333);
      }
      .vp-title{ font-weight:600; }
      .vp-body{
        padding:.5rem; display:flex; flex-direction:column; gap:.5rem; overflow:hidden;
      }
      .vp-search{ flex:0 0 auto; }

      .vp-split{
        flex:1 1 auto; min-height: 0;
        display:flex; gap:.5rem; overflow:hidden;
      }

      .vp-tree{
        flex: 0 0 220px;
        overflow:auto; padding:.25rem;
        border:1px solid var(--bs-border-color,#333);
        border-radius:.5rem;
        background: var(--bs-tertiary-bg, rgba(255,255,255,.02));
      }

      .vp-results{
        flex: 1 1 auto;
        overflow:auto; padding-bottom:2.5rem;
      }

      .vp-tree-node{
        width:100%; text-align:left;
        border:1px solid transparent;
        background: transparent;
        color: inherit;
        padding:.35rem .4rem;
        border-radius:.45rem;
        margin-bottom:.25rem;
        cursor:pointer;
      }
      .vp-tree-node:hover{
        background: rgba(255,255,255,.06);
        border-color: rgba(255,255,255,.08);
      }
      .vp-tree-node.is-selected{
        background: rgba(13,110,253,.18);
        border-color: rgba(13,110,253,.35);
      }
      .vp-tree-node-main{
        display:flex; align-items:center; justify-content:space-between; gap:.5rem;
      }
      .vp-tree-node-label{ font-weight: 600; font-size:.9rem; }
      .vp-tree-node-mono{
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
        font-size:.75rem; color: var(--bs-secondary-color,#bbb);
        word-break: break-all;
        margin-top:.15rem;
      }
      .vp-tree-count{
        font-size:.75rem;
        padding:.1rem .35rem;
        border-radius:999px;
        border:1px solid rgba(255,255,255,.15);
        color: var(--bs-secondary-color,#bbb);
      }

      .vp-tree-group{
        margin:.25rem 0 .45rem;
        border:1px solid rgba(255,255,255,.08);
        border-radius:.5rem;
        overflow:hidden;
      }
      .vp-tree-group-title{
        list-style:none;
        cursor:pointer;
        user-select:none;
        padding:.35rem .4rem;
        display:flex; align-items:center; justify-content:space-between; gap:.5rem;
        background: rgba(255,255,255,.03);
      }
      .vp-tree-group-title::-webkit-details-marker{ display:none; }
      .vp-tree-items{ padding:.25rem .35rem .35rem; }

      .vp-group{
        font-size:.75rem; letter-spacing:.02em;
        color: var(--bs-secondary-color,#aaa);
        text-transform:uppercase;
        margin:.6rem .25rem .35rem;
      }
      .vp-results-head{
        font-size:.8rem;
        color: var(--bs-secondary-color,#aaa);
        margin:.2rem .25rem .35rem;
      }
      .vp-item{
        display:flex; align-items:center; justify-content:space-between; gap:.5rem;
        padding:.5rem;
        border:1px solid var(--bs-border-color,#333);
        border-radius:.5rem;
        background: var(--bs-tertiary-bg, rgba(255,255,255,.02));
        margin-bottom:.5rem;
      }
      .vp-item-text{ min-width:0; }
      .vp-item-title{ font-weight:600; margin-bottom:.15rem; }
      .vp-item-sub{
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
        font-size:.8rem; color: var(--bs-secondary-color,#bbb);
        word-break: break-all;
      }
      .vp-item-actions{ display:flex; align-items:center; gap:.4rem; flex:0 0 auto; }
      .vp-empty{ padding:.5rem; }

      .vp-footer{ padding:.4rem .6rem; border-top:1px solid var(--bs-border-color,#333); }

      .vp-toast{
        position:absolute; bottom:.6rem; left:50%; transform:translateX(-50%);
        background: rgba(0,0,0,.8); color:#fff;
        padding:.35rem .6rem; border-radius:.4rem;
        font-size:.8rem; opacity:0;
        transition:opacity .15s ease; pointer-events:none;
      }
      .vp-toast.show{ opacity:1; }

      /* Push main content so buttons are not covered */
      .vp-open .tp-main { margin-right: 580px; }
      @media (max-width: 920px) { .vp-open .tp-main { margin-right: min(580px, 30vw); } }
    `;
    document.head.appendChild(css);
  }
}
