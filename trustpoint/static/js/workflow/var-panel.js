// static/js/workflow/var-panel.js
import { fetchContextCatalog, buildStepsGroup } from './ui-context.js';
import { insertIntoActive, getActiveTemplatable } from './template-fields.js';

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
    this._selectedStepNo = 1;

    this._lastCatalogKey = null;
    this._lastCatalog = { groups: [] };

    // Insert formatting mode:
    // - "auto" => raw if focused field requests raw, else template
    // - "template" => always {{ ctx.* }}
    // - "raw" => always ctx.*
    this._insertMode = 'auto';

    // Prevent async catalog races from overwriting latest render
    this._renderToken = 0;
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
        <div class="vp-footer-row">
          <div>
            Tip: focus a field, then click <strong>Insert</strong>. Press <kbd>Ctrl</kbd>/<kbd>⌘</kbd>+<kbd>K</kbd> to toggle.
          </div>
          <div class="vp-insertmode" role="group" aria-label="Insert mode">
            <button type="button" class="btn btn-sm btn-outline-secondary vp-mode" data-mode="auto">Auto</button>
            <button type="button" class="btn btn-sm btn-outline-secondary vp-mode" data-mode="template">Template</button>
            <button type="button" class="btn btn-sm btn-outline-secondary vp-mode" data-mode="raw">Raw</button>
          </div>
        </div>
        <div class="vp-footnote">
          Auto inserts <code>ctx.*</code> for fields marked <code>data-tpl-mode="raw"</code>, otherwise <code>{{ ctx.* }}</code>.
        </div>
      </div>
    `;
    document.body.appendChild(panel);

    this.root = panel;
    this.searchEl = panel.querySelector('.vp-search');
    this.treeEl = panel.querySelector('.vp-tree');
    this.resultsEl = panel.querySelector('.vp-results');

    panel.querySelector('.vp-close').onclick = () => this.close();
    this.searchEl.addEventListener('input', () => this._render());

    // Insert mode buttons
    panel.querySelectorAll('.vp-mode').forEach((btn) => {
      btn.onclick = () => {
        const mode = String(btn.dataset.mode || 'auto');
        this._insertMode = (mode === 'template' || mode === 'raw') ? mode : 'auto';
        this._syncInsertModeButtons();
        this._toast(`Insert mode: ${this._insertMode}`);
      };
    });
    this._syncInsertModeButtons();

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

  _syncInsertModeButtons() {
    if (!this.root) return;
    this.root.querySelectorAll('.vp-mode').forEach((btn) => {
      const m = String(btn.dataset.mode || '');
      btn.classList.toggle('btn-primary', m === this._insertMode);
      btn.classList.toggle('btn-outline-secondary', m !== this._insertMode);
    });
  }

  _focusedWantsRaw() {
    const el = getActiveTemplatable();
    if (!el || !(el instanceof HTMLElement)) return false;
    return String(el.dataset.tplMode || '').toLowerCase() === 'raw';
  }

  _formatInsert(ctxPath) {
    const path = String(ctxPath || '').trim();
    if (!path) return '';

    const mode = this._insertMode;

    if (mode === 'raw') return path;
    if (mode === 'template') return `{{ ${path} }}`;

    // auto
    return this._focusedWantsRaw() ? path : `{{ ${path} }}`;
  }

  async _render() {
    if (!this.treeEl || !this.resultsEl) return;

    const token = ++this._renderToken;

    const st = (typeof this.getState === 'function') ? this.getState() : {};
    const handler = String(st?.handler || '').trim();
    const protocol = String(st?.protocol || '').trim();
    const operation = String(st?.operation || '').trim();
    const stepCount = Array.isArray(st?.steps) ? st.steps.length : 0;

    // Keep step selector valid
    if (this._selectedStepNo < 1) this._selectedStepNo = 1;
    if (stepCount > 0 && this._selectedStepNo > stepCount) this._selectedStepNo = stepCount;
    if (stepCount === 0) this._selectedStepNo = 1;

    const selectedStepType =
      (Array.isArray(st?.steps) && st.steps[this._selectedStepNo - 1] && st.steps[this._selectedStepNo - 1].type) || '';

    const catalogKey = `h=${handler}::p=${protocol}::o=${operation}`;

    // Fetch only if handler/protocol/operation changed
    if (catalogKey !== this._lastCatalogKey) {
      this._lastCatalogKey = catalogKey;

      if (!handler) {
        this._lastCatalog = { groups: [] };
      } else {
        try {
          const data = await fetchContextCatalog({ handler, protocol, operation });
          // Guard against in-flight stale completion
          if (token !== this._renderToken || catalogKey !== this._lastCatalogKey) return;
          this._lastCatalog = data || { groups: [] };
        } catch {
          if (token !== this._renderToken || catalogKey !== this._lastCatalogKey) return;
          this._lastCatalog = { groups: [] };
        }
      }

      // Reset group selection on catalog key change
      this._selectedGroupKey = null;
    }

    // Normalize groups and de-dupe
    let groups = this._normalizeGroups(this._lastCatalog.groups || []);

    // Always remove backend Steps group; we inject exactly one clean Steps group
    groups = groups.filter(g => String(g.key) !== 'steps' && String(g.label).toLowerCase() !== 'steps');

    // Inject Steps group
    groups = this._insertStepsGroup(groups, { stepCount, selectedStepType });

    // De-dupe again
    groups = this._dedupeGroupsByLabelAndVars(groups);

    // Default selection
    if (!this._selectedGroupKey && groups.length) this._selectedGroupKey = groups[0].key;

    this._renderTree(groups);
    this._renderResults(groups, { stepCount });
  }

  _insertStepsGroup(groups, { stepCount, selectedStepType }) {
    const stepsGroup = buildStepsGroup({
      stepCount,
      selectedStepNo: this._selectedStepNo,
      selectedStepType,
    });

    // Put Steps before Saved Vars if present, else at end
    const out = [];
    let inserted = false;

    for (const g of groups) {
      const isSavedVars = (String(g.label).toLowerCase() === 'saved vars') || (String(g.key) === 'vars');
      if (!inserted && isSavedVars) {
        out.push(stepsGroup);
        inserted = true;
      }
      out.push(g);
    }

    if (!inserted) out.push(stepsGroup);
    return out;
  }

  _normalizeGroups(groups) {
    return (groups || []).map((g, gi) => {
      const key = String(g.key || g.name || `group_${gi}`);
      const label = String(g.label || g.name || key);

      const vars = (g.vars || []).map((v, vi) => {
        const raw = v.key || v.path || '';
        const ctxPath = String(raw).startsWith('ctx.') ? String(raw) : `ctx.${String(raw)}`;
        return {
          key: String(v.key || v.path || `var_${gi}_${vi}`),
          label: String(v.label || v.key || v.path || ctxPath),
          ctxPath,
        };
      });

      return { key, label, vars };
    });
  }

  _dedupeGroupsByLabelAndVars(groups) {
    const normLabel = (s) => String(s || '').trim().toLowerCase();

    const map = new Map();
    for (const g of groups) {
      const lk = normLabel(g.label);
      if (!map.has(lk)) {
        map.set(lk, { ...g, key: g.key || lk, vars: [...(g.vars || [])] });
        continue;
      }
      const cur = map.get(lk);
      const seen = new Set(cur.vars.map(v => v.ctxPath));
      for (const v of (g.vars || [])) {
        if (!seen.has(v.ctxPath)) {
          cur.vars.push(v);
          seen.add(v.ctxPath);
        }
      }
    }

    const out = [];
    const seenLabels = new Set();
    for (const g of groups) {
      const lk = normLabel(g.label);
      if (seenLabels.has(lk)) continue;
      seenLabels.add(lk);
      out.push(map.get(lk));
    }
    return out;
  }

  _renderTree(groups) {
    const frag = document.createDocumentFragment();

    for (const g of groups) {
      frag.appendChild(this._treeNode({
        key: g.key,
        label: g.label,
        count: g.vars.length,
        selected: this._selectedGroupKey === g.key,
        onClick: () => {
          this._selectedGroupKey = g.key;
          this._render();
        },
      }));
    }

    this.treeEl.innerHTML = '';
    this.treeEl.appendChild(frag);
  }

  _treeNode({ key, label, count = null, selected = false, onClick }) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `vp-tree-node${selected ? ' is-selected' : ''}`;
    btn.dataset.key = key;
    btn.innerHTML = `
      <div class="vp-tree-node-main">
        <span class="vp-tree-node-label">${this._esc(label)}</span>
        ${count != null ? `<span class="vp-tree-count">${count}</span>` : ''}
      </div>
    `;
    btn.onclick = onClick;
    return btn;
  }

  _renderResults(groups, { stepCount }) {
    const q = (this.searchEl?.value || '').trim().toLowerCase();
    const frag = document.createDocumentFragment();

    if (q) {
      const visible = [];
      for (const g of groups) {
        for (const v of g.vars) {
          const label = String(v.label || '');
          const path = String(v.ctxPath || '');
          if (label.toLowerCase().includes(q) || path.toLowerCase().includes(q)) {
            visible.push({ groupLabel: g.label, ...v });
          }
        }
      }

      visible.sort((a, b) => {
        const gcmp = String(a.groupLabel).localeCompare(String(b.groupLabel));
        if (gcmp !== 0) return gcmp;
        return String(a.label).localeCompare(String(b.label));
      });

      const head = document.createElement('div');
      head.className = 'vp-results-head';
      head.textContent = `Matches: ${visible.length}`;
      frag.appendChild(head);

      let lastGroup = null;
      for (const v of visible) {
        if (v.groupLabel !== lastGroup) {
          lastGroup = v.groupLabel;
          const gh = document.createElement('div');
          gh.className = 'vp-group';
          gh.textContent = v.groupLabel;
          frag.appendChild(gh);
        }
        frag.appendChild(this._resultRow(v));
      }

      if (!visible.length) {
        const empty = document.createElement('div');
        empty.className = 'vp-empty text-muted small';
        empty.textContent = 'No matches.';
        frag.appendChild(empty);
      }

      this.resultsEl.innerHTML = '';
      this.resultsEl.appendChild(frag);
      return;
    }

    const sel = groups.find(x => x.key === this._selectedGroupKey) || groups[0];

    if (sel && String(sel.key) === 'steps') {
      frag.appendChild(this._stepsHeader({ stepCount }));
    }

    if (sel && sel.vars.length) {
      for (const v of sel.vars) frag.appendChild(this._resultRow(v));
    } else {
      const empty = document.createElement('div');
      empty.className = 'vp-empty text-muted small';
      empty.textContent = 'No variables available.';
      frag.appendChild(empty);
    }

    this.resultsEl.innerHTML = '';
    this.resultsEl.appendChild(frag);
  }

  _stepsHeader({ stepCount }) {
    const wrap = document.createElement('div');
    wrap.className = 'vp-results-head';

    const row = document.createElement('div');
    row.style.display = 'flex';
    row.style.alignItems = 'center';
    row.style.justifyContent = 'space-between';
    row.style.gap = '.5rem';

    const label = document.createElement('div');
    label.textContent = 'Select step:';

    const sel = document.createElement('select');
    sel.className = 'form-select form-select-sm';
    sel.style.maxWidth = '180px';
    sel.disabled = !(stepCount > 0);

    if (stepCount <= 0) {
      sel.add(new Option('No steps', '0'));
    } else {
      for (let i = 1; i <= stepCount; i += 1) sel.add(new Option(`step_${i}`, String(i)));
      sel.value = String(this._selectedStepNo);
    }

    sel.onchange = () => {
      this._selectedStepNo = Number(sel.value || '1') || 1;
      this._render();
    };

    row.appendChild(label);
    row.appendChild(sel);
    wrap.appendChild(row);
    return wrap;
  }

  _resultRow(v) {
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
      const text = this._formatInsert(v.ctxPath);
      const ok = insertIntoActive(text);
      if (!ok) this._toast('Focus a field first.');
    };

    copyBtn.onclick = async () => {
      const text = this._formatInsert(v.ctxPath);
      try {
        await navigator.clipboard.writeText(text);
        this._toast('Copied!');
      } catch {
        this._toast('Copy failed.');
      }
    };

    return row;
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
      .vp-tree-count{
        font-size:.75rem;
        padding:.1rem .35rem;
        border-radius:999px;
        border:1px solid rgba(255,255,255,.15);
        color: var(--bs-secondary-color,#bbb);
      }
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
      .vp-footer{ padding:.45rem .6rem; border-top:1px solid var(--bs-border-color,#333); }
      .vp-footer-row{
        display:flex; align-items:center; justify-content:space-between; gap:.5rem; flex-wrap:wrap;
      }
      .vp-insertmode{ display:flex; gap:.35rem; }
      .vp-footnote{ margin-top:.35rem; opacity:.9; }
      .vp-toast{
        position:absolute; bottom:.6rem; left:50%; transform:translateX(-50%);
        background: rgba(0,0,0,.8); color:#fff;
        padding:.35rem .6rem; border-radius:.4rem;
        font-size:.8rem; opacity:0;
        transition:opacity .15s ease; pointer-events:none;
      }
      .vp-toast.show{ opacity:1; }
      .vp-open .tp-main { margin-right: 580px; }
      @media (max-width: 920px) { .vp-open .tp-main { margin-right: min(580px, 30vw); } }
    `;
    document.head.appendChild(css);
  }
}
