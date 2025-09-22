// static/js/workflow/executors/email.js
import { register, ui } from './index.js';
import { state } from '../state.js';
import { markTemplatable } from '../template-fields.js';

/* ----------------- Minimal inline Chips widget (no extra file) ----------------- */
let _chipsCSSInjected = false;
function injectChipsCSS() {
  if (_chipsCSSInjected) return;
  _chipsCSSInjected = true;
  const css = document.createElement('style');
  css.id = 'chips-inline-css';
  css.textContent = `
    .chips { display:flex; align-items:center; gap:.35rem; flex-wrap:wrap;
             min-height:2.25rem; padding:.375rem .5rem; border:1px solid var(--bs-border-color,#ced4da);
             border-radius:.375rem; background:var(--bs-body-bg,#fff); }
    .chips:focus-within { outline:2px solid var(--bs-primary,#0d6efd); outline-offset:1px; }
    .chip { display:inline-flex; align-items:center; gap:.35rem; padding:.1rem .5rem;
            border-radius:999px; background:var(--bs-secondary-bg, #e9ecef);
            border:1px solid var(--bs-border-color,#ced4da); font-size:.875rem; }
    .chip-x { cursor:pointer; border:none; background:transparent; line-height:1;
              font-size:1rem; padding:0 .15rem; opacity:.6; }
    .chip-x:hover { opacity:1; }
    .chips-input { flex:1 1 120px; min-width:120px; border:none; outline:none; background:transparent; }
    .chips-input::placeholder { color: var(--bs-secondary-color,#6c757d); }
  `;
  document.head.appendChild(css);
}
function _splitCSV(s) {
  return String(s || '').split(',').map(x => x.trim()).filter(Boolean);
}
function _toCSV(arr) {
  return (arr || []).map(x => String(x).trim()).filter(Boolean).join(',');
}
class Chips {
  constructor({ value = '', placeholder = 'Add…', onChange } = {}) {
    injectChipsCSS();
    this.items = _splitCSV(value);
    this.onChange = typeof onChange === 'function' ? onChange : () => {};
    this.root = document.createElement('div');
    this.root.className = 'chips';
    this.input = document.createElement('input');
    this.input.type = 'text';
    this.input.className = 'chips-input';
    this.input.placeholder = placeholder;

    this.root.addEventListener('click', () => this.input.focus());

    this.input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === 'Tab' || e.key === ',') {
        const v = this.input.value.trim();
        if (v) this._add(v);
        this.input.value = '';
        if (e.key !== ',') e.preventDefault();
      } else if (e.key === 'Backspace' && !this.input.value && this.items.length) {
        this._remove(this.items.length - 1);
        e.preventDefault();
      }
    });

    this.input.addEventListener('paste', (e) => {
      const text = (e.clipboardData?.getData('text') || '').trim();
      if (!text) return;
      const parts = text.split(/[\n,]+/).map(s => s.trim()).filter(Boolean);
      if (parts.length > 1) {
        e.preventDefault();
        parts.forEach(p => this._add(p));
        this._notify();
      }
    });

    this.input.addEventListener('blur', () => {
      const v = this.input.value.trim();
      if (v) {
        this._add(v);
        this.input.value = '';
        this._notify();
      }
    });

    this._render();
  }
  el() { return this.root; }
  setCSV(value) { this.items = _splitCSV(value); this._render(); this._notify(); }

  _add(token) { if (!token) return; this.items.push(token); this._render(); this._notify(); }
  _remove(idx) { if (idx < 0 || idx >= this.items.length) return; this.items.splice(idx, 1); this._render(); this._notify(); }

  _render() {
    this.root.innerHTML = '';
    this.items.forEach((t, i) => {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = t;
      const x = document.createElement('button');
      x.type = 'button';
      x.className = 'chip-x';
      x.setAttribute('aria-label', 'Remove');
      x.textContent = '×';
      x.onclick = () => this._remove(i);
      chip.appendChild(x);
      this.root.appendChild(chip);
    });
    this.root.appendChild(this.input);
  }
  _notify() {
    try { this.onChange(_toCSV(this.items), this.items.slice()); } catch {}
  }
}
/* --------------------------------------------------------------------- */

function firstTemplateKey() {
  for (const g of (state.mailTemplates?.groups || [])) {
    if ((g.templates || []).length) return g.templates[0].key;
  }
  return '';
}
function groupForTemplate(tplKey) {
  const gg = state.mailTemplates?.groups || [];
  for (const g of gg) if ((g.templates || []).some(t => t.key === tplKey)) return g.key;
  return '';
}
function fillTemplatesForGroup(groupKey, sel) {
  sel.innerHTML = '';
  const g = (state.mailTemplates?.groups || []).find(x => x.key === groupKey);
  (g?.templates || []).forEach(t => sel.add(new Option(t.label || t.key, t.key)));
  if (!sel.value && sel.options.length) sel.selectedIndex = 0;
}

register('Email', {
  getDefaultParams() {
    return {
      recipients: '',
      from_email: '',
      cc: '',
      bcc: '',
      template: '',   // if set → template mode; else subject/body → custom mode
      subject: '',
      body: '',
    };
  },

  renderParams(container, step, { updateStepParam, onChange }) {
    container.textContent = '';

    // Recipients (chips)
    const toChips = new Chips({
      value: step.params.recipients || '',
      placeholder: 'Add recipient, press Enter…',
      onChange: (csv) => { updateStepParam(step.id, 'recipients', csv); onChange(); },
    });
    container.appendChild(ui.labeledNode('Recipients', toChips.el()));

    // From (single), CC (chips), BCC (chips)
    const rowTop = ui.row();

    rowTop.appendChild(
      ui.col(
        ui.labeledNode(
          'From (optional)',
          ui.input({
            type: 'email',
            value: step.params.from_email || '',
            onInput: (v) => { updateStepParam(step.id, 'from_email', v); onChange(); },
          }),
        ),
        'col-md-4',
      ),
    );

    const ccChips = new Chips({
      value: step.params.cc || '',
      placeholder: 'Add CC…',
      onChange: (csv) => { updateStepParam(step.id, 'cc', csv); onChange(); },
    });
    rowTop.appendChild(ui.col(ui.labeledNode('CC (optional)', ccChips.el()), 'col-md-4'));

    const bccChips = new Chips({
      value: step.params.bcc || '',
      placeholder: 'Add BCC…',
      onChange: (csv) => { updateStepParam(step.id, 'bcc', csv); onChange(); },
    });
    rowTop.appendChild(ui.col(ui.labeledNode('BCC (optional)', bccChips.el()), 'col-md-4'));

    container.appendChild(rowTop);

    // Mode: template vs custom
    const useTpl = !!(step.params.template && String(step.params.template).trim());
    const modeWrap = document.createElement('div');
    modeWrap.className = 'my-2';

    const tpl = ui.radio(`email-mode-${step.id}`, 'Use template', useTpl, () => {
      updateStepParam(step.id, 'subject', '');
      updateStepParam(step.id, 'body', '');
      if (!step.params.template) {
        const first = firstTemplateKey();
        if (first) updateStepParam(step.id, 'template', first);
      }
      this.renderParams(container, step, { updateStepParam, onChange });
      onChange();
    });
    const custom = ui.radio(`email-mode-${step.id}`, 'Write custom', !useTpl, () => {
      updateStepParam(step.id, 'template', '');
      this.renderParams(container, step, { updateStepParam, onChange });
      onChange();
    });

    modeWrap.appendChild(tpl.wrap);
    modeWrap.appendChild(custom.wrap);
    container.appendChild(modeWrap);

    // Template block
    const tplBlock = document.createElement('div');
    tplBlock.className = useTpl ? '' : 'd-none';
    const groups = (state.mailTemplates && Array.isArray(state.mailTemplates.groups)) ? state.mailTemplates.groups : [];

    const groupSel = document.createElement('select');
    groupSel.className = 'form-select form-select-sm';
    groups.forEach(g => groupSel.add(new Option(g.label || g.key, g.key)));

    const tplSel = document.createElement('select');
    tplSel.className = 'form-select form-select-sm';

    const currentTpl = step.params.template || '';
    const currentGroup = groupForTemplate(currentTpl) || (groups[0]?.key || '');
    groupSel.value = currentGroup;
    fillTemplatesForGroup(currentGroup, tplSel);
    if (currentTpl && [...tplSel.options].some(o => o.value === currentTpl)) tplSel.value = currentTpl;

    groupSel.onchange = () => {
      fillTemplatesForGroup(groupSel.value, tplSel);
      updateStepParam(step.id, 'template', tplSel.value || '');
      onChange();
    };
    tplSel.onchange = () => { updateStepParam(step.id, 'template', tplSel.value || ''); onChange(); };

    const tplRow = ui.row();
    tplRow.appendChild(ui.col(ui.labeledNode('Template group', groupSel)));
    tplRow.appendChild(ui.col(ui.labeledNode('Template', tplSel)));
    tplBlock.appendChild(tplRow);
    container.appendChild(tplBlock);

    // Custom block
    const customBlock = document.createElement('div');
    customBlock.className = useTpl ? 'd-none mt-2' : 'mt-2';

    const subjInput = ui.input({
      type: 'text',
      value: step.params.subject || '',
      onInput: (v) => { updateStepParam(step.id, 'subject', v); onChange(); },
    });
    const bodyArea = (function () {
      const el = document.createElement('textarea');
      el.className = 'form-control form-control-sm';
      el.rows = 4;
      el.value = step.params.body || '';
      el.oninput = () => { updateStepParam(step.id, 'body', el.value); onChange(); };
      return el;
    }());

    markTemplatable(subjInput);
    markTemplatable(bodyArea);

    // Optional: reflect mode in controls
    subjInput.disabled = useTpl;
    bodyArea.disabled = useTpl;

    customBlock.appendChild(ui.labeledNode('Subject', subjInput));
    customBlock.appendChild(ui.labeledNode('Body (plain text)', bodyArea));
    container.appendChild(customBlock);
  },

  validate(params) {
    const errs = [];
    const to = String(params.recipients || '').trim();
    if (!to) errs.push('Email: at least one recipient is required.');
    const usingTemplate = !!(params.template && String(params.template).trim());
    if (!usingTemplate) {
      if (!params.subject || !String(params.subject).trim()) errs.push('Email: subject is required in custom mode.');
      if (!params.body || !String(params.body).trim())       errs.push('Email: body is required in custom mode.');
    }
    return errs;
  },
});
