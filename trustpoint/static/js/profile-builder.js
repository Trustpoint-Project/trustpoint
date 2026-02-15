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

  resolveFieldPath(json, field) {
    let val = this.getValueAt(json, field.fullPath);
    if (val !== undefined) return { value: val, path: field.fullPath };

    if (field.aliases && Array.isArray(field.aliases)) {
      for (const alias of field.aliases) {
        val = this.getValueAt(json, alias);
        if (val !== undefined) return { value: val, path: alias };
      }
    }
    return { value: undefined, path: field.fullPath };
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

    const resolved = this.resolveFieldPath(currentJson, field);
    const existingData = resolved.value;
    const targetPath = resolved.path;

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

    // --- CASE 1: Profile Property ---
    if (isProfileProperty) {
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
                   data-path="${this.escapeHtml(targetPath)}"
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
    // --- CASE 2: Containers ---
    else if (hasChildren) {
      formContent = `${descriptionHtml}<div style="max-height:400px; overflow-y:auto; padding-right:5px;">`;
      childFields.forEach(child => {
        const childResolved = this.resolveFieldPath(currentJson, child);
        const childVal = childResolved.value;
        const childPath = childResolved.path;

        let effectiveValue = childVal;
        let isMutable = false;

        if (childVal && typeof childVal === 'object' && !Array.isArray(childVal)) {
            if (childVal.value !== undefined) effectiveValue = childVal.value;
            else if (childVal.default !== undefined) effectiveValue = childVal.default;
            else effectiveValue = undefined;

            if (childVal.mutable === true) isMutable = true;
        }

        if (child.valueType === 'boolean') {
          const isChecked = effectiveValue === true ? 'checked' : '';
          formContent += `
            <div class="pb-checkbox-wrapper">
              <label>
                <input type="checkbox" class="pb-input-child"
                       data-path="${this.escapeHtml(childPath)}"
                       data-type="boolean" ${isChecked}>
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
          let minAttr = '';

          if (child.valueType === 'list') {
             valStr = Array.isArray(effectiveValue) ? effectiveValue.join(', ') : '';
             placeholder = 'a, b, c';
          } else if (child.valueType === 'number') {
             typeAttr = 'number';
             minAttr = 'min="0"'; // FIX 1: Prevent negative path lengths
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
                  <input type="checkbox" class="pb-child-mutable"
                         data-path="${this.escapeHtml(childPath)}" ${mutChecked}>
                  Mutable
                </label>
              </div>
              <input type="${typeAttr}" class="pb-input-child"
                     data-path="${this.escapeHtml(childPath)}"
                     data-type="${child.valueType}" ${minAttr}
                     value="${this.escapeHtml(valStr)}" placeholder="${placeholder}">
              <div class="pb-input-desc">${this.escapeHtml(child.description)}</div>
            </div>`;
        }
      });
      formContent += `</div>`;
    }
    // --- CASE 3: Simple Values (Fix 2: Handle reject_mods as checkbox) ---
    else {
      const valStr = (existingData !== undefined && existingData !== null) ? existingData : '';
      const inputType = field.valueType === 'number' ? 'number' : 'text';
      let suggestions = '';

      if (field.fullPath.includes('reject_mods') || field.valueType === 'boolean') {
          // Render as Checkbox
          const isChecked = existingData === true ? 'checked' : '';
          formContent = `
            ${descriptionHtml}
            <div class="pb-checkbox-wrapper">
              <label>
                <input type="checkbox" id="pb-single-input"
                       data-path="${this.escapeHtml(targetPath)}"
                       data-type="boolean" ${isChecked}>
                <span class="pb-checkbox-label">
                  <span class="pb-label-title">${this.escapeHtml(field.name)}</span>
                  <span class="pb-label-desc">Enable to reject unknown fields.</span>
                </span>
              </label>
            </div>`;
      } else {
          // Normal Input
          if (field.suggestions) {
            suggestions = `<div class="pb-suggestions">` + field.suggestions.map(s =>
              `<button type="button" class="pb-suggestion-btn" data-val="${this.escapeHtml(s)}">${this.escapeHtml(s)}</button>`
            ).join('') + `</div>`;
          }

          let minAttr = (field.valueType === 'number') ? 'min="0"' : ''; // FIX 1 applied here too

          formContent = `
            ${descriptionHtml}
            <div class="pb-input-wrapper">
              <label>Value</label>
              ${suggestions}
              <input type="${inputType}" id="pb-single-input"
                     data-path="${this.escapeHtml(targetPath)}" ${minAttr}
                     value="${this.escapeHtml(valStr)}"
                     placeholder="${this.escapeHtml(field.expectedHint || '')}">
            </div>`;
      }
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
      const updates = {};

      if (isProfileProperty) {
        const val = modal.querySelector('#pp-value').value;
        const req = modal.querySelector('#pp-required').checked;
        const mut = modal.querySelector('#pp-mutable').checked;
        const path = modal.querySelector('#pp-value').getAttribute('data-path');

        if (req || mut) {
          const obj = {};
          if (val) {
             if (mut) obj.default = val;
             else obj.value = val;
          }
          if (mut) obj.mutable = true;
          if (req) obj.required = true;
          updates[path] = obj;
        } else {
          // FIX 3: Correctly handle unsetting both flags with empty value
          if (val) {
             updates[path] = { value: val };
          } else {
             // Explicitly set undefined to delete the key from JSON
             updates[path] = undefined;
          }
        }
      }
      else if (hasChildren) {
        modal.querySelectorAll('.pb-input-child').forEach(input => {
          const path = input.getAttribute('data-path');
          const type = input.getAttribute('data-type');
          let val = null;

          if (type === 'boolean') {
            if (input.checked) updates[path] = true;
            else {
                // If unchecked, check if we need to remove it
                // Logic: If user specifically unchecks, we remove the key (undefined)
                // This assumes default state is false/undefined.
                updates[path] = undefined;
            }
          } else {
            if (type === 'list') {
                if (input.value.trim()) val = input.value.split(',').map(s => s.trim()).filter(Boolean);
            } else {
                if (input.value) val = type === 'number' ? Number(input.value) : input.value;
            }

            if (val !== null && val !== '') {
                const mutBox = modal.querySelector(`.pb-child-mutable[data-path="${path}"]`);
                const isMutable = mutBox ? mutBox.checked : false;

                if (isMutable) {
                    updates[path] = { default: val, mutable: true };
                } else {
                    updates[path] = { value: val, mutable: false };
                }
            } else {
                // Input cleared -> Remove key
                updates[path] = undefined;
            }
          }
        });
      }
      else {
        // Simple
        const input = modal.querySelector('#pb-single-input');
        const path = input.getAttribute('data-path');
        const type = input.getAttribute('data-type');

        if (type === 'boolean') {
            updates[path] = input.checked; // true or false
        } else {
            const raw = input.value;
            if (raw === '') {
                updates[path] = undefined; // Remove if empty
            } else {
                const val = field.valueType === 'number' ? Number(raw) : raw;
                updates[path] = val;
            }
        }
      }

      this.batchUpdateJson(updates);
      closeModal();
    });
  }

  batchUpdateJson(updates) {
    try {
      let json = {};
      try { json = JSON.parse(this.editor.value); } catch(e) {}

      for (const [pathStr, value] of Object.entries(updates)) {
          const keys = pathStr.split('.');
          let current = json;

          // Handle Delete (value === undefined)
          if (value === undefined) {
              for (let i = 0; i < keys.length - 1; i++) {
                  if (!current[keys[i]]) break; // path doesn't exist
                  current = current[keys[i]];
              }
              delete current[keys[keys.length - 1]];
              // Cleanup empty objects? Optional, but cleaner.
              continue;
          }

          // Handle Insert/Update
          for (let i = 0; i < keys.length - 1; i++) {
            const key = keys[i];
            if (!current[key]) current[key] = {};
            current = current[key];
          }
          current[keys[keys.length - 1]] = value;
      }

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