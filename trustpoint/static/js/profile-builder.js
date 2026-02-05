class CertificateProfileBuilder {
  constructor(editorElementId = 'json-editor', sidebarElementId = 'profile-builder-sidebar') {
    this.editor = document.getElementById(editorElementId);
    this.sidebar = document.getElementById(sidebarElementId);
    this.searchInput = document.getElementById('profile-builder-search');
    this.fieldsContainer = document.getElementById('profile-builder-fields');

    this.fieldCatalog = this.initializeFieldCatalog();
    this.allFields = this.flattenFieldCatalog();

    this.currentJson = this.parseEditorJson();
    this.filteredFields = this.allFields;
    this.sidebarOpen = false;

    this.init();
  }


  initializeFieldCatalog() {
    return {
      GENERAL: {
        label: 'General',
        description: 'Top-level fields',
        icon: '',
        fields: [
          {
            name: 'type',
            fullPath: 'type',
            description: 'Profile type (expected: "cert_profile")',
            valueType: 'string',
            expectedHint: 'Expected: string, e.g. "cert_profile".'
          },
          {
            name: 'ver',
            fullPath: 'ver',
            description: 'Schema version (expected format: "1.0")',
            valueType: 'string',
            expectedHint: 'Expected: string version, e.g. "1.0".'
          }
        ]
      },
      DISPLAY_NAME: {
        label: 'Display Name',
        description: 'Human readable name',
        icon: '',
        fields: [
          {
            name: 'display_name',
            fullPath: 'display_name',
            description: 'Profile display name (string)',
            valueType: 'string',
            expectedHint: 'Expected: string, e.g. "Example Certificate Profile".'
          }
        ]
      },
      SUBJECT: {
        label: 'Subject',
        description: 'Subject DN',
        icon: '',
        fields: [
          {
            name: 'subject.allow',
            fullPath: 'subject.allow',
            description: 'Allowed subject attributes (e.g. "*" or ["CN","OU"])',
            valueType: 'string',
            expectedHint: 'Expected: "*" or JSON list like ["CN","OU"].'
          },
          {


            name: 'subject.CN',
            fullPath: 'subject.CN',
            description: 'Common Name (value + required)',
            valueType: 'composite_cn',
            expectedHint: 'Value: string, e.g. "device.example.com"; Required: checkbox.'
          },
          {
            name: 'subject.OU',
            fullPath: 'subject.OU',
            description: 'Organizational Unit (nullable, use null to prohibit)',
            valueType: 'nullable',
            expectedHint: 'Expected: null to prohibit, or a string value.'
          }
        ]
      },
      EXT: {
        label: 'Extensions',
        description: 'X.509 extensions',
        icon: '',
        fields: [
          {
            name: 'ext.allow',
            fullPath: 'ext.allow',
            description: 'Extensions allow mask (string or list, e.g. "*")',
            valueType: 'string',
            expectedHint: 'Expected: "*" or JSON list like ["key_usage","san"].'
          },
          {

            name: 'ext.key_usage',
            fullPath: 'ext.key_usage',
            description: 'Key usage flags (digital_signature, key_encipherment, critical)',
            valueType: 'composite_key_usage',
            expectedHint: 'Produces: {"digital_signature":true/false,"key_encipherment":true/false,"critical":true/false}.'
          },
          {

            name: 'ext.extended_key_usage',
            fullPath: 'ext.extended_key_usage',
            description: 'Extended key usages list (e.g. ["server_auth","client_auth"])',
            valueType: 'composite_eku',
            expectedHint: 'Value becomes: {"usages":["server_auth","client_auth"]}.'
          },
          {

            name: 'ext.san',
            fullPath: 'ext.san',
            description: 'Subject Alternative Names (DNS + IP lists)',
            valueType: 'composite_san',
            expectedHint: 'Value becomes: {"dns":["device.example.com"],"ip":["192.0.2.1"]}.'
          },
          {


            name: 'ext.basic_constraints',
            fullPath: 'ext.basic_constraints',
            description: 'Basic constraints (CA + critical)',
            valueType: 'composite_basic_constraints',
            expectedHint: 'Value becomes: {"ca":true/false,"critical":true/false}.'
          }
        ]
      },
      VALIDITY: {
        label: 'Validity',
        description: 'Validity period',
        icon: '',
        fields: [
          {

            name: 'validity.days',
            fullPath: 'validity.days',
            description: 'Validity in days (number, suggestions: 30 / 60 / 90)',
            valueType: 'number',
            suggestions: [30, 60, 90],
            expectedHint: 'Expected: integer number of days, e.g. 42.'
          }
        ]
      }
    };
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
      }
    });


    document.addEventListener('click', (e) => {
      const modal = document.querySelector('.profile-builder-modal');
      if (!modal) return;
      const clickedInside = modal.contains(e.target);
      if (!clickedInside) modal.remove();
    });

    this.renderFields();
  }

  toggleSidebar() {
    this.sidebarOpen = !this.sidebarOpen;
    if (this.sidebar) {
      this.sidebar.classList.toggle('tp-pb-visible', this.sidebarOpen);
    }
    if (this.sidebarOpen) {
      this.searchInput?.focus();
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = '';
      if (this.searchInput) this.searchInput.value = '';
      this.filteredFields = this.allFields;
      this.renderFields();
    }
  }

  openSidebar() { if (!this.sidebarOpen) this.toggleSidebar(); }
  closeSidebar() { if (this.sidebarOpen) this.toggleSidebar(); }

  filterFields(query) {
    const q = query.toLowerCase().trim();
    this.filteredFields = !q ? this.allFields : this.allFields.filter(field =>
      field.name.toLowerCase().includes(q) ||
      field.description.toLowerCase().includes(q) ||
      field.fullPath.toLowerCase().includes(q) ||
      field.sectionLabel.toLowerCase().includes(q)
    );
    this.renderFields();
  }

  renderFields() {
    if (!this.fieldsContainer) return;

    if (!Array.isArray(this.filteredFields) || this.filteredFields.length === 0) {
      this.fieldsContainer.innerHTML = '<div class="profile-builder-no-results">No fields found</div>';
      return;
    }

    this.fieldsContainer.innerHTML = '';
    const grouped = {};
    this.filteredFields.forEach(field => {
      if (!field || !field.section) return;
      if (!grouped[field.section]) grouped[field.section] = [];
      grouped[field.section].push(field);
    });

    Object.entries(grouped).forEach(([section, fields]) => {
      const sectionData = this.fieldCatalog[section];
      if (!sectionData) return;

      const sectionEl = document.createElement('div');
      sectionEl.className = 'profile-builder-section';
      sectionEl.innerHTML = `
        <div class="profile-builder-section-header">
          <span class="profile-builder-section-icon">${sectionData.icon}</span>
          <span class="profile-builder-section-label">${sectionData.label}</span>
        </div>
      `;

      fields.forEach(field => {
        const fieldEl = document.createElement('div');
        fieldEl.className = 'profile-builder-field';
        fieldEl.innerHTML = `
          <div class="profile-builder-field-info">
            <div class="profile-builder-field-name">${field.name}</div>
            <div class="profile-builder-field-description">${field.description}</div>
            <div class="profile-builder-field-path">${field.fullPath}</div>
          </div>
          <div class="profile-builder-field-actions">
            <button class="profile-builder-btn-insert" title="Insert into JSON">Insert</button>
            <button class="profile-builder-btn-copy" data-path="${field.fullPath}" title="Copy path">Copy</button>
          </div>
        `;

        fieldEl.querySelector('.profile-builder-btn-insert')
          .addEventListener('click', (e) => {
            e.stopPropagation();
            this.showValuePopup(field);
          });

        fieldEl.querySelector('.profile-builder-btn-copy')
          .addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.copyToClipboard(field.fullPath, e.target);
          });

        fieldEl.addEventListener('click', () => this.showValuePopup(field));

        sectionEl.appendChild(fieldEl);
      });

      this.fieldsContainer.appendChild(sectionEl);
    });
  }

  showValuePopup(field) {
    const existing = document.querySelector('.profile-builder-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.className = 'profile-builder-modal';
    const close = () => modal.remove();

    const hint = field.expectedHint || 'Enter JSON or plain string. For null, type null.';

    let bodyInner = '';


    if (field.valueType === 'composite_cn') {
      bodyInner = `
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Common Name</div>
          <div style="display:flex;flex-direction:column;gap:12px;">
            <div>
              <label class="form-label">Value (default)</label>
              <input type="text" id="pb-cn-value" class="profile-builder-custom-input"
                     placeholder='Example: "device.example.com"'>
              <div style="margin-top:4px;font-size:11px;color:var(--color-text-secondary);">
                ${hint}
              </div>
            </div>
            <label style="display:flex;align-items:center;gap:8px;">
              <input type="checkbox" id="pb-cn-required" checked>
              Required
            </label>
            <div style="display:flex;justify-content:flex-end;">
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
          </div>
        </div>
      `;
    }


    else if (field.valueType === 'composite_key_usage') {
      bodyInner = `
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Key Usage</div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <label style="display:flex;align-items:center;gap:8px;">
              <input type="checkbox" id="pb-ku-ds" checked>
              digital_signature
            </label>
            <label style="display:flex;align-items:center;gap:8px;">
              <input type="checkbox" id="pb-ku-ke" checked>
              key_encipherment
            </label>
            <label style="display:flex;align-items:center;gap:8px;">
              <input type="checkbox" id="pb-ku-critical" checked>
              critical
            </label>
            <div style="margin-top:4px;font-size:11px;color:var(--color-text-secondary);">
              ${hint}
            </div>
            <div style="display:flex;justify-content:flex-end;margin-top:8px;">
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
          </div>
        </div>
      `;
    }


    else if (field.valueType === 'composite_eku') {
      bodyInner = `
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Extended Key Usage</div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <label class="form-label">Usages (comma separated)</label>
            <input type="text" id="pb-eku-list" class="profile-builder-custom-input"
                   value="server_auth, client_auth">
            <div style="margin-top:4px;font-size:11px;color:var(--color-text-secondary);">
              ${hint}
            </div>
            <div style="display:flex;justify-content:flex-end;margin-top:8px;">
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
          </div>
        </div>
      `;
    }


    else if (field.valueType === 'composite_san') {
      bodyInner = `
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Subject Alternative Names</div>
          <div style="display:flex;flex-direction:column;gap:12px;">
            <div>
              <label class="form-label">DNS names (comma separated)</label>
              <input type="text" id="pb-san-dns" class="profile-builder-custom-input"
                     value="device.example.com">
            </div>
            <div>
              <label class="form-label">IP addresses (comma separated)</label>
              <input type="text" id="pb-san-ip" class="profile-builder-custom-input"
                     value="192.0.2.1">
            </div>
            <div style="margin-top:4px;font-size:11px;color:var(--color-text-secondary);">
              ${hint}
            </div>
            <div style="display:flex;justify-content:flex-end;">
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
          </div>
        </div>
      `;
    }


    else if (field.valueType === 'composite_basic_constraints') {
      bodyInner = `
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Basic Constraints</div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <label style="display:flex;align-items:center;gap:8px;">
              <input type="checkbox" id="pb-bc-ca">
              CA
            </label>
            <label style="display:flex;align-items:center;gap:8px;">
              <input type="checkbox" id="pb-bc-critical" checked>
              Critical
            </label>
            <div style="margin-top:4px;font-size:11px;color:var(--color-text-secondary);">
              ${hint}
            </div>
            <div style="display:flex;justify-content:flex-end;margin-top:8px;">
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
          </div>
        </div>
      `;
    }


    else if (field.valueType === 'number') {
      const suggestions = (field.suggestions || []).map(v => `
        <button class="profile-builder-template-btn" data-number="${v}">
          <div class="profile-builder-template-label">${v} days</div>
        </button>
      `).join('');
      bodyInner = `
        ${suggestions ? `
          <div class="profile-builder-divider">Suggestions</div>
          <div class="profile-builder-templates">
            ${suggestions}
          </div>
        ` : ''}
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Custom value</div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            <div style="display:flex;gap:8px;align-items:center;">
              <input type="number" id="pb-custom-number" class="profile-builder-custom-input"
                     placeholder="e.g. 42">
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
            <div style="font-size:11px;color:var(--color-text-secondary);">
              ${hint}
            </div>
          </div>
        </div>
      `;
    }


    else {
      bodyInner = `
        <div class="profile-builder-custom-section">
          <div class="profile-builder-divider">Value</div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            <div style="display:flex;gap:8px;align-items:center;">
              <textarea id="pb-custom-text" class="profile-builder-custom-input" rows="3"
                placeholder='${hint}'></textarea>
              <button class="profile-builder-custom-btn">Apply</button>
            </div>
            <div style="font-size:11px;color:var(--color-text-secondary);">
              ${hint}
            </div>
          </div>
        </div>
      `;
    }

    modal.innerHTML = `
      <div class="profile-builder-modal-content">
        <div class="profile-builder-modal-header">
          <h3>Set value for <code>${field.fullPath}</code></h3>
          <button class="profile-builder-modal-close">&times;</button>
        </div>
        <div class="profile-builder-modal-body">
          ${bodyInner}
        </div>
      </div>
    `;

    modal.querySelector('.profile-builder-modal-close').addEventListener('click', close);

    const applyBtn = modal.querySelector('.profile-builder-custom-btn');

    if (field.valueType === 'composite_cn') {
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const valueInput = modal.querySelector('#pb-cn-value').value.trim();
        const value = valueInput || 'device.example.com';
        const required = modal.querySelector('#pb-cn-required').checked;
        this.insertField(field, { required, default: value });
        close();
      });
    } else if (field.valueType === 'composite_key_usage') {
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const ds = modal.querySelector('#pb-ku-ds').checked;
        const ke = modal.querySelector('#pb-ku-ke').checked;
        const critical = modal.querySelector('#pb-ku-critical').checked;
        this.insertField(field, {
          digital_signature: ds,
          key_encipherment: ke,
          critical: critical
        });
        close();
      });
    } else if (field.valueType === 'composite_eku') {
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const raw = modal.querySelector('#pb-eku-list').value.trim();
        const usages = raw ? raw.split(',').map(s => s.trim()).filter(Boolean) : [];
        this.insertField(field, { usages });
        close();
      });
    } else if (field.valueType === 'composite_san') {
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const dnsRaw = modal.querySelector('#pb-san-dns').value.trim();
        const ipRaw = modal.querySelector('#pb-san-ip').value.trim();
        const dns = dnsRaw ? dnsRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
        const ip = ipRaw ? ipRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
        this.insertField(field, { dns, ip });
        close();
      });
    } else if (field.valueType === 'composite_basic_constraints') {
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const ca = modal.querySelector('#pb-bc-ca').checked;
        const critical = modal.querySelector('#pb-bc-critical').checked;
        this.insertField(field, { ca, critical });
        close();
      });
    } else if (field.valueType === 'number') {
      modal.querySelectorAll('.profile-builder-template-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
          e.preventDefault();
          const v = Number(btn.getAttribute('data-number'));
          this.insertField(field, v);
          close();
        });
      });
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const v = Number(modal.querySelector('#pb-custom-number').value);
        if (!Number.isFinite(v)) {
          this.showNotification('Please enter a valid number', 'error');
          return;
        }
        this.insertField(field, v);
        close();
      });
    } else {
      applyBtn.addEventListener('click', (e) => {
        e.preventDefault();
        const raw = modal.querySelector('#pb-custom-text').value.trim();
        if (!raw) {
          this.showNotification('Please enter a value', 'error');
          return;
        }
        let value;
        try {
          value = JSON.parse(raw);
        } catch {
          value = raw;
        }
        this.insertField(field, value);
        close();
      });
    }

    document.body.appendChild(modal);
  }

  insertField(field, value) {
    try {
      let json = this.parseEditorJson();
      const path = field.fullPath.split('.');
      let current = json;

      for (let i = 0; i < path.length - 1; i++) {
        const key = path[i];
        if (current[key] === undefined) current[key] = {};
        current = current[key];
      }

      current[path.at(-1)] = value;
      this.updateEditor(json);
      this.showNotification(`Inserted ${field.fullPath}`, 'success');
    } catch (error) {
      console.error('Insert error:', error);
      this.showNotification(`Insert failed: ${error.message}`, 'error');
    }
  }

  parseEditorJson() {
    try {
      return JSON.parse(this.editor.value);
    } catch {
      return { type: 'cert_profile', ver: '1.0' };
    }
  }

  updateEditor(json) {
    this.editor.value = JSON.stringify(json, null, 2);
    this.editor.dispatchEvent(new Event('input', { bubbles: true }));
    this.editor.dispatchEvent(new Event('change', { bubbles: true }));
    this.validateJson();
    this.editor.focus();
    this.editor.scrollTop = this.editor.scrollHeight;
  }

  validateJson() {
    try {
      JSON.parse(this.editor.value);
      this.editor.classList.remove('is-invalid');
      this.editor.classList.add('is-valid');
      const errorEl = document.getElementById('profile_json_error');
      if (errorEl) errorEl.textContent = '';
      return true;
    } catch (error) {
      this.editor.classList.remove('is-valid');
      this.editor.classList.add('is-invalid');
      const errorEl = document.getElementById('profile_json_error');
      if (errorEl) errorEl.textContent = `Invalid JSON: ${error.message}`;
      return false;
    }
  }

  copyToClipboard(text, button) {
    navigator.clipboard.writeText(text).then(() => {
      const orig = button.textContent;
      button.textContent = '✓ Copied';
      setTimeout(() => button.textContent = orig, 2000);
    }).catch(console.error);
  }

  showNotification(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `profile-builder-toast profile-builder-toast-${type}`;
    toast.textContent = message;
    document.body.appendChild(toast);
    setTimeout(() => toast.classList.add('visible'), 10);
    setTimeout(() => {
      toast.classList.remove('visible');
      setTimeout(() => toast.remove(), 300);
    }, 3000);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.getElementById('profile-builder-sidebar')) {
    window.profileBuilder = new CertificateProfileBuilder();
  }
});
