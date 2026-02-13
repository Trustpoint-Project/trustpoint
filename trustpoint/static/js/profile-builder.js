class CertificateProfileBuilder {
  constructor(editorElementId = 'json-editor', sidebarElementId = 'profile-builder-sidebar') {
    this.editor = document.getElementById(editorElementId);
    this.sidebar = document.getElementById(sidebarElementId);
    this.searchInput = document.getElementById('profile-builder-search');
    this.fieldsContainer = document.getElementById('profile-builder-fields');

    this.fieldCatalog = window.initializeFieldCatalog();
    this.allFields = this.flattenFieldCatalog();
    this.filteredFields = this.allFields;
    this.sidebarOpen = false;

    this.init();
  }

  flattenFieldCatalog() {
    const flattened = [];
    for (const [section, data] of Object.entries(this.fieldCatalog)) {
      for (const field of data.fields) {
        flattened.push({ ...field, section, sectionLabel: data.label, sectionIcon: data.icon });
      }
    }
    return flattened;
  }

  init() {
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        this.toggleSidebar();
      }
    });

    const closeBtn = this.sidebar?.querySelector('.tp-pb-close');
    if (closeBtn) closeBtn.addEventListener('click', () => this.closeSidebar());

    const triggerBtn = document.getElementById('profile-builder-trigger-btn');
    if (triggerBtn) {
      triggerBtn.addEventListener('click', (e) => {
        e.preventDefault();
        this.toggleSidebar();
      });
    }

    if (this.searchInput) {
      this.searchInput.addEventListener('input', (e) => this.filterFields(e.target.value));
      this.searchInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') e.preventDefault();
      });
    }

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const modal = document.querySelector('.profile-builder-modal');
        if (modal) modal.remove();
        else if (this.sidebarOpen) this.closeSidebar();
      }
    });

    this.renderFields();
  }

  toggleSidebar() {
    this.sidebarOpen = !this.sidebarOpen;
    if (this.sidebar) {
      this.sidebar.classList.toggle('tp-pb-visible', this.sidebarOpen);
      if (this.sidebarOpen) {
        if (this.searchInput) this.searchInput.focus();
        document.body.style.overflow = 'hidden';
      } else {
        document.body.style.overflow = '';
      }
    }
  }

  closeSidebar() {
    if (this.sidebarOpen) this.toggleSidebar();
  }

  filterFields(query) {
    if (!query) {
      this.filteredFields = this.allFields;
    } else {
      const q = query.toLowerCase();
      this.filteredFields = this.allFields.filter(f =>
        f.name.toLowerCase().includes(q) ||
        f.fullPath.toLowerCase().includes(q)
      );
    }
    this.renderFields();
  }

  renderFields() {
    if (!this.fieldsContainer) return;
    this.fieldsContainer.innerHTML = '';

    if (this.filteredFields.length === 0) {
      this.fieldsContainer.innerHTML = '<div style="padding:20px; text-align:center; color:#888;">No fields found</div>';
      return;
    }

    const grouped = {};
    this.filteredFields.forEach(field => {
      const parts = field.fullPath.split('.');
      let isHiddenChild = false;
      if (parts.length > 1) {
        const parentPath = parts.slice(0, -1).join('.');
        const parentExists = this.allFields.some(f => f.fullPath === parentPath);
        if (parentExists) isHiddenChild = true;
      }
      if (isHiddenChild) return;

      if (!grouped[field.section]) grouped[field.section] = [];
      grouped[field.section].push(field);
    });

    Object.entries(grouped).forEach(([section, fields]) => {
      if (fields.length === 0) return;

      const sectionHeader = document.createElement('div');
      sectionHeader.className = 'profile-builder-section-header';
      sectionHeader.innerHTML = `
        <span class="profile-builder-section-icon">${fields[0].sectionIcon}</span>
        <span class="profile-builder-section-label">${fields[0].sectionLabel}</span>
      `;
      this.fieldsContainer.appendChild(sectionHeader);

      fields.forEach(field => {
        const btn = document.createElement('div');
        btn.className = 'profile-builder-field';
        btn.innerHTML = `
          <div class="profile-builder-field-info">
            <div class="profile-builder-field-name">${field.name}</div>
            <div class="profile-builder-field-path">${field.fullPath}</div>
          </div>
        `;
        btn.addEventListener('click', () => this.showValuePopup(field));
        this.fieldsContainer.appendChild(btn);
      });
    });
  }

  getValueAt(obj, pathStr) {
    if (!obj) return undefined;
    const path = pathStr.split('.');
    let current = obj;
    for (const key of path) {
      if (current === undefined || current === null) return undefined;
      current = current[key];
    }
    return current;
  }

  escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  showValuePopup(field) {
    const existing = document.querySelector('.profile-builder-modal');
    if (existing) existing.remove();

    let currentJson = {};
    try { currentJson = JSON.parse(this.editor.value); } catch (e) {}


    let descriptionHtml = '';
    if (field.description) {
      descriptionHtml = `
        <div style="background:#f8f9fa; padding:10px; border-radius:6px; margin-bottom:16px; border:1px solid #e9ecef; color:#555; font-size:13px; line-height:1.4;">
          <strong>Description:</strong> ${this.escapeHtml(field.description)}
        </div>
      `;
    }

    let formContent = '';
    const isProfileProperty = field.valueType === 'profile_property';
    const childFields = this.allFields.filter(f => f.fullPath.startsWith(field.fullPath + '.'));
    const hasChildren = childFields.length > 0;


    if (isProfileProperty) {
      const existingData = this.getValueAt(currentJson, field.fullPath);
      let val = '';
      let req = false;
      let mut = false;

      if (existingData && typeof existingData === 'object' && !Array.isArray(existingData)) {
        if (existingData.value !== undefined) val = existingData.value;
        else if (existingData.default !== undefined) val = existingData.default;

        if (existingData.required === true) req = true;
        if (existingData.mutable === true) mut = true;
      } else if (existingData !== undefined && existingData !== null) {
        val = existingData;
      }

      formContent = `
        ${descriptionHtml}
        <div style="display:flex; flex-direction:column; gap:16px;">
          <div class="pb-input-wrapper">
            <label>Value / Default</label>
            <input type="text" id="pp-value" class="pb-input-child"
                   value="${this.escapeHtml(val)}" placeholder="Value or Default...">
            <div class="pb-input-desc">The specific value for this field.</div>
          </div>
          <div style="display:flex; gap:24px; padding:4px 0;">
            <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
              <input type="checkbox" id="pp-mutable" ${mut ? 'checked' : ''}>
              <span style="font-weight:500;">Mutable</span>
            </label>
            <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
              <input type="checkbox" id="pp-required" ${req ? 'checked' : ''}>
              <span style="font-weight:500;">Required</span>
            </label>
          </div>
        </div>`;
    }

    else if (hasChildren) {
      formContent = `${descriptionHtml}<div style="max-height:400px; overflow-y:auto; padding-right:5px;">`;
      childFields.forEach(child => {
        const shortKey = child.fullPath.replace(field.fullPath + '.', '');
        const existingData = this.getValueAt(currentJson, child.fullPath);


        let effectiveValue = existingData;
        let isMutable = false;

        if (existingData && typeof existingData === 'object' && !Array.isArray(existingData)) {
            if (existingData.value !== undefined) effectiveValue = existingData.value;
            else if (existingData.default !== undefined) effectiveValue = existingData.default;
            else effectiveValue = undefined;

            if (existingData.mutable === true) isMutable = true;
        }


        if (child.valueType === 'boolean') {
          const isChecked = effectiveValue === true ? 'checked' : '';
          formContent += `
            <div class="pb-checkbox-wrapper">
              <label>
                <input type="checkbox" class="pb-input-child" data-key="${this.escapeHtml(shortKey)}" data-type="boolean" ${isChecked}>
                <span class="pb-checkbox-label">
                  <span class="pb-label-title">${this.escapeHtml(child.name)}</span>
                  <span class="pb-label-desc">${this.escapeHtml(child.description)}</span>
                </span>
              </label>
            </div>`;


        } else {

          let typeAttr = 'text';
          let placeholder = 'Value...';
          let valStr = '';

          if (child.valueType === 'list') {
             valStr = Array.isArray(effectiveValue) ? effectiveValue.join(', ') : '';
             placeholder = 'a, b, c';
          } else if (child.valueType === 'number') {
             typeAttr = 'number';
             valStr = (effectiveValue !== undefined && effectiveValue !== null) ? effectiveValue : '';
          } else {
             valStr = (effectiveValue !== undefined && effectiveValue !== null) ? effectiveValue : '';
          }

          const mutChecked = isMutable ? 'checked' : '';


          formContent += `
            <div class="pb-input-wrapper">
              <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
                <label style="margin:0;">${this.escapeHtml(child.name)}</label>
                <label style="font-weight:normal; font-size:12px; display:flex; align-items:center; gap:4px; cursor:pointer;">
                  <input type="checkbox" class="pb-child-mutable" data-key="${this.escapeHtml(shortKey)}" ${mutChecked}>
                  Mutable
                </label>
              </div>
              <input type="${typeAttr}" class="pb-input-child" data-key="${this.escapeHtml(shortKey)}" data-type="${child.valueType}"
                     value="${this.escapeHtml(valStr)}" placeholder="${placeholder}">
              <div class="pb-input-desc">${this.escapeHtml(child.description)}</div>
            </div>`;
        }
      });
      formContent += `</div>`;
    }

    else {
      const existingValue = this.getValueAt(currentJson, field.fullPath);
      const valStr = (existingValue !== undefined && existingValue !== null) ? existingValue : '';
      const inputType = field.valueType === 'number' ? 'number' : 'text';

      let suggestions = '';
      if (field.suggestions) {
        suggestions = `<div class="pb-suggestions">` + field.suggestions.map(s =>
          `<button type="button" class="pb-suggestion-btn" data-val="${this.escapeHtml(s)}">${this.escapeHtml(s)}</button>`
        ).join('') + `</div>`;
      }

      formContent = `
        ${descriptionHtml}
        <div class="pb-input-wrapper">
          <label>Value</label>
          ${suggestions}
          <input type="${inputType}" id="pb-single-input" value="${this.escapeHtml(valStr)}" placeholder="${this.escapeHtml(field.expectedHint || '')}">
        </div>`;
    }

    const modal = document.createElement('div');
    modal.className = 'profile-builder-modal';

    const contentDiv = document.createElement('div');
    contentDiv.className = 'profile-builder-modal-content';

    const headerDiv = document.createElement('div');
    headerDiv.className = 'profile-builder-modal-header';
    const titleH3 = document.createElement('h3');
    titleH3.textContent = field.name;
    const closeBtn = document.createElement('button');
    closeBtn.className = 'close-btn';
    closeBtn.innerHTML = '&times;';

    headerDiv.appendChild(titleH3);
    headerDiv.appendChild(closeBtn);

    const bodyDiv = document.createElement('div');
    bodyDiv.className = 'profile-builder-modal-body';
    bodyDiv.innerHTML = formContent;

    const footerDiv = document.createElement('div');
    footerDiv.className = 'profile-builder-modal-footer';
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'cancel-btn';
    cancelBtn.textContent = 'Cancel';
    const applyBtn = document.createElement('button');
    applyBtn.className = 'apply-btn';
    applyBtn.textContent = 'Insert';

    footerDiv.appendChild(cancelBtn);
    footerDiv.appendChild(applyBtn);

    contentDiv.appendChild(headerDiv);
    contentDiv.appendChild(bodyDiv);
    contentDiv.appendChild(footerDiv);
    modal.appendChild(contentDiv);

    document.body.appendChild(modal);


    const closeModal = () => modal.remove();
    closeBtn.addEventListener('click', closeModal);
    cancelBtn.addEventListener('click', closeModal);

    modal.querySelectorAll('.pb-suggestion-btn').forEach(b => {
      b.addEventListener('click', () => {
        modal.querySelector('#pb-single-input').value = b.dataset.val;
      });
    });

    applyBtn.addEventListener('click', () => {
      let finalValue;

      if (isProfileProperty) {
        const val = modal.querySelector('#pp-value').value;
        const req = modal.querySelector('#pp-required').checked;
        const mut = modal.querySelector('#pp-mutable').checked;

        if (req || mut) {
          finalValue = {};
          if (val) {

             if (mut) finalValue.default = val;
             else finalValue.value = val;
          }
          if (mut) finalValue.mutable = true;
          if (req) finalValue.required = true;
        } else {
          if (val) finalValue = { value: val };
          else finalValue = undefined;
        }
      } else if (hasChildren) {
        finalValue = {};


        modal.querySelectorAll('.pb-input-child').forEach(input => {
          const key = input.dataset.key;
          const type = input.dataset.type;
          let val = null;

          if (type === 'boolean') {
            if (input.checked) finalValue[key] = true;

          } else {

            if (type === 'list') {
                if (input.value.trim()) val = input.value.split(',').map(s => s.trim()).filter(Boolean);
            } else {
                if (input.value) val = type === 'number' ? Number(input.value) : input.value;
            }

            if (val !== null) {

                const mutBox = modal.querySelector(`.pb-child-mutable[data-key="${key}"]`);
                const isMutable = mutBox ? mutBox.checked : false;

                if (isMutable) {
                    finalValue[key] = { default: val, mutable: true };
                } else {

                    finalValue[key] = { value: val, mutable: false };
                }
            }
          }
        });
      } else {
        const raw = modal.querySelector('#pb-single-input').value;
        finalValue = field.valueType === 'number' ? Number(raw) : raw;
      }

      if (finalValue !== undefined) {
        this.insertFieldIntoJson(field.fullPath, finalValue);
      }
      closeModal();
    });
  }

  insertFieldIntoJson(pathStr, value) {
    try {
      let json = {};
      try { json = JSON.parse(this.editor.value); } catch(e) {}

      const keys = pathStr.split('.');
      let current = json;
      for (let i = 0; i < keys.length - 1; i++) {
        const key = keys[i];
        if (!current[key]) current[key] = {};
        current = current[key];
      }
      current[keys[keys.length - 1]] = value;

      this.editor.value = JSON.stringify(json, null, 2);
      this.editor.dispatchEvent(new Event('input', { bubbles: true }));
    } catch (e) {
      alert("Invalid JSON in editor. Cannot insert.");
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('profile-builder-sidebar')) {
    window.profileBuilder = new CertificateProfileBuilder();
  }
});