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
  'DISPLAY_NAME': {
      label: 'Display Name',
      description: 'Human readable profile name',
      icon: '📝',
      fields: [
        {
          name: 'display_name',
          fullPath: 'display_name',
          description: 'Profile display name',
          templates: [
            { label: 'Required', value: { required: true, default: 'TLS Client' } },
            { label: 'Custom', value: "REPLACE IT WITH DISPLAY NAME" },
            { label: 'Fixed string', value: 'TLS Client' }
          ]
        }
      ]
    },
    'SUBJECT': {
      label: 'Subject',
      description: 'Certificate subject fields (DN)',
      icon: '👤',
      fields: [
        {
          name: 'CN',
          fullPath: 'subject.CN',
          description: 'Common Name',
          templates: [
            { label: 'Required, mutable', value: { required: true } },
            { label: 'Required, default value', value: { required: true, default: 'Trustpoint Credential' } },
            { label: 'Fixed value (immutable)', value: 'Trustpoint Credential' },
            { label: 'Optional (empty)', value: {} },
            { label: 'With regex validation', value: { required: true, re: '^[a-zA-Z0-9.-]+$' } },
            { label: 'Prohibited', value: null }
          ]
        },

        {
          name: 'O',
          fullPath: 'subject.O',
          description: 'Organization Name',
          templates: [
            { label: 'Fixed value', value: 'My Organization' },
            { label: 'Required', value: { required: true } },
            { label: 'Optional', value: {} },
            { label: 'Prohibited', value: null }
          ]
        },
        {
          name: 'OU',
          fullPath: 'subject.OU',
          description: 'Organizational Unit',
          templates: [
            { label: 'Fixed value', value: 'Security' },
            { label: 'Mutable with default', value: { required: true, default: 'Engineering' } },
            { label: 'Optional', value: {} },
            { label: 'Prohibited', value: null }
          ]
        },
        {
          name: 'C',
          fullPath: 'subject.C',
          description: 'Country (2-letter code)',
          templates: [
            { label: 'Fixed value', value: 'DE' },
            { label: 'With regex (2-letter)', value: { required: true, re: '^[A-Z]{2}$' } },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'ST',
          fullPath: 'subject.ST',
          description: 'State/Province',
          templates: [
            { label: 'Fixed value', value: 'Rheinland-Pfalz' },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'L',
          fullPath: 'subject.L',
          description: 'Locality/City',
          templates: [
            { label: 'Fixed value', value: 'Mayen' },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'SN',
          fullPath: 'subject.SN',
          description: 'Surname',
          templates: [
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'GN',
          fullPath: 'subject.GN',
          description: 'Given Name',
          templates: [
            { label: 'Optional', value: {} }
          ]
        }
      ]
    },
    'EXTENSIONS': {
      label: 'Extensions',
      description: 'X.509 certificate extensions',
      icon: '🔐',
      fields: [
        {
          name: 'subjectAltName',
          fullPath: 'extensions.subjectAltName',
          description: 'Subject Alternative Name extension',
          templates: [
            {
              label: 'Required with DNS names',
              value: {
                required: true,
                dnsNames: { required: true },
                ipAddresses: { required: false }
              }
            },
            {
              label: 'Required, DNS + IP allowed',
              value: {
                required: true,
                dnsNames: {},
                ipAddresses: {}
              }
            },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'keyUsage',
          fullPath: 'extensions.keyUsage',
          description: 'Key Usage extension',
          templates: [
            {
              label: 'Digital Signature only',
              value: {
                digitalSignature: true,
                keyEncipherment: null,
                critical: {}
              }
            },
            {
              label: 'TLS Server (digitalSignature + keyEncipherment)',
              value: {
                digitalSignature: true,
                keyEncipherment: true,
                critical: {}
              }
            },
            {
              label: 'CA Certificate (keyCertSign + cRLsign)',
              value: {
                keyCertSign: true,
                cRLsign: true,
                critical: { value: true }
              }
            },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'basicConstraints',
          fullPath: 'extensions.basicConstraints',
          description: 'Basic Constraints extension',
          templates: [
            {
              label: 'End-entity (not CA)',
              value: { ca: false, pathLenConstraint: null }
            },
            {
              label: 'CA with path length 0',
              value: { ca: true, pathLenConstraint: 0 }
            },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'extendedKeyUsage',
          fullPath: 'extensions.extendedKeyUsage',
          description: 'Extended Key Usage (EKU)',
          templates: [
            { label: 'TLS Server', value: { serverAuth: true } },
            { label: 'TLS Client', value: { clientAuth: true } },
            { label: 'Code Signing', value: { codeSigning: true } },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'subjectKeyIdentifier',
          fullPath: 'extensions.subjectKeyIdentifier',
          description: 'Subject Key Identifier',
          templates: [
            { label: 'Auto-generated', value: { auto: true } },
            { label: 'Optional', value: {} }
          ]
        },
        {
          name: 'authorityKeyIdentifier',
          fullPath: 'extensions.authorityKeyIdentifier',
          description: 'Authority Key Identifier',
          templates: [
            { label: 'Auto-generated', value: { auto: true } },
            { label: 'Optional', value: {} }
          ]
        }
      ]
    },
    'VALIDITY': {
      label: 'Validity',
      description: 'Certificate validity period settings',
      icon: '📅',
      fields: [
        {
          name: 'days',
          fullPath: 'validity.days',
          description: 'Validity period in days',
          templates: [
            { label: '90 days', value: 90 },
            { label: '365 days (1 year)', value: 365 },
            { label: '1826 days (5 years)', value: 1826 },
            { label: '3650 days (10 years)', value: 3650 }
          ]
        },
        {
          name: 'duration',
          fullPath: 'validity.duration',
          description: 'ISO 8601 duration format (e.g., P365D)',
          templates: [
            { label: '90 days (P90D)', value: 'P90D' },
            { label: '365 days (P365D)', value: 'P365D' },
            { label: '1 year (P1Y)', value: 'P1Y' }
          ]
        },
        {
          name: 'notBefore',
          fullPath: 'validity.notBefore',
          description: 'Explicit ISO 8601 timestamp (notBefore)',
          templates: [
            { label: 'Now (ISO 8601)', value: new Date().toISOString() }
          ]
        },
        {
          name: 'notAfter',
          fullPath: 'validity.notAfter',
          description: 'Explicit ISO 8601 timestamp (notAfter)',
          templates: [
            { label: 'Far future', value: '99991231T235959Z' }
          ]
        },
        {
          name: 'offset_s',
          fullPath: 'validity.offset_s',
          description: 'Offset in seconds (e.g., for clock skew)',
          templates: [
            { label: '-3600 (1 hour backdate)', value: -3600 },
            { label: '-300 (5 minutes backdate)', value: -300 }
          ]
        }
      ]
    },
    'CONSTRAINTS': {
      label: 'Constraints',
      description: 'Global constraint settings',
      icon: '⚙️',
      fields: [
        {
          name: 'mutable',
          fullPath: 'mutable',
          description: 'Global mutable flag (default: false)',
          templates: [
            { label: 'true - Allow overrides', value: true },
            { label: 'false - Immutable', value: false }
          ]
        },
        {
          name: 'allow',
          fullPath: 'allow',
          description: 'Global allow list (undefined = only explicit, "*" = all)',
          templates: [
            { label: 'All fields allowed ("*")', value: '*' },
            { label: 'Only explicit fields', value: [] },
            { label: 'Specific allow list', value: ['CN', 'O', 'OU', 'C'] }
          ]
        },
        {
          name: 'reject_mods',
          fullPath: 'reject_mods',
          description: 'Reject request if any field cannot be modified',
          templates: [
            { label: 'true - Strict validation', value: true },
            { label: 'false - Permissive', value: false }
          ]
        },
        {
          name: 'required',
          fullPath: 'required',
          description: 'Required fields',
          templates: [
            { label: 'List of required fields', value: ['CN', 'O'] }
          ]
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
    console.log('CertificateProfileBuilder init');
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
      if (e.key === 'Escape' && this.sidebarOpen) this.closeSidebar();
    });

    // FIXED: Only close sidebar if clicking OUTSIDE the sidebar AND modal
    document.addEventListener('click', (e) => {
      const isClickInsideSidebar = this.sidebar && this.sidebar.contains(e.target);
      const isClickInsideModal = document.querySelector('.profile-builder-modal')?.contains(e.target);

      if (this.sidebarOpen && !isClickInsideSidebar && !isClickInsideModal) {
        this.closeSidebar();
      }
    });

    this.renderFields();
  }

  toggleSidebar() { this.sidebarOpen ? this.closeSidebar() : this.openSidebar(); }

  openSidebar() {
    this.sidebarOpen = true;
    this.sidebar?.classList.add('tp-pb-visible');
    this.searchInput?.focus();
    document.body.style.overflow = 'hidden';
  }

  closeSidebar() {
    this.sidebarOpen = false;
    this.sidebar?.classList.remove('tp-pb-visible');
    document.body.style.overflow = '';
    this.searchInput.value = '';
    this.filteredFields = this.allFields;
    this.renderFields();
  }

  filterFields(query) {
    const q = query.toLowerCase().trim();
    this.filteredFields = !q ? this.allFields : this.allFields.filter(field =>
      field.name.toLowerCase().includes(q) || field.description.toLowerCase().includes(q) ||
      field.fullPath.toLowerCase().includes(q) || field.sectionLabel.toLowerCase().includes(q)
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
             .addEventListener('click', () => this.showTemplateSelector(field));
      fieldEl.querySelector('.profile-builder-btn-copy')
             .addEventListener('click', (e) => {
               e.preventDefault();
               this.copyToClipboard(field.fullPath, e.target);
             });

      sectionEl.appendChild(fieldEl);
    });

    this.fieldsContainer.appendChild(sectionEl);
  });
}


  showTemplateSelector(field) {
    if (field.templates.length === 1) return this.insertField(field, field.templates[0]);

    const modal = document.createElement('div');
    modal.className = 'profile-builder-modal';
    modal.innerHTML = `
      <div class="profile-builder-modal-content">
        <div class="profile-builder-modal-header">
          <h3>Select template for <code>${field.name}</code></h3>
          <button class="profile-builder-modal-close">&times;</button>
        </div>
        <div class="profile-builder-modal-body"></div>
      </div>
    `;

    const bodyEl = modal.querySelector('.profile-builder-modal-body');

    // Add template buttons
    field.templates.forEach((t, idx) => {
      const btn = document.createElement('button');
      btn.className = 'profile-builder-template-btn';
      btn.innerHTML = `
        <div class="profile-builder-template-label">${t.label}</div>
        <code>${JSON.stringify(t.value).substring(0, 60)}${JSON.stringify(t.value).length > 60 ? '...' : ''}</code>
      `;
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        this.insertField(field, field.templates[idx]);
        modal.remove();
      });
      bodyEl.appendChild(btn);
    });

    // Add custom input section
    const customDiv = document.createElement('div');
    customDiv.className = 'profile-builder-custom-section';
    customDiv.innerHTML = `
      <div class="profile-builder-divider">Or enter a custom value</div>
      <div style="display: flex; gap: 8px; margin-top: 12px;">
        <input type="text"
               id="custom-value-input"
               class="profile-builder-custom-input"
               placeholder="Enter custom value (JSON format)" />
        <button class="profile-builder-custom-btn">Add Custom</button>
      </div>
    `;

    bodyEl.appendChild(customDiv);

    const customInput = customDiv.querySelector('#custom-value-input');
    const customBtn = customDiv.querySelector('.profile-builder-custom-btn');

    const insertCustom = () => {
      const inputValue = customInput.value.trim();
      if (!inputValue) {
        this.showNotification('Please enter a value', 'error');
        return;
      }

      try {
        let value;
        try {
          value = JSON.parse(inputValue);
        } catch {
          value = inputValue;
        }

        this.insertField(field, { label: 'Custom', value });
        modal.remove();
      } catch (error) {
        this.showNotification(`Error: ${error.message}`, 'error');
      }
    };

    customBtn.addEventListener('click', (e) => {
      e.preventDefault();
      insertCustom();
    });

    customInput.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        insertCustom();
      }
    });

    modal.querySelector('.profile-builder-modal-close').addEventListener('click', () => modal.remove());
    modal.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') modal.remove();
    });

    document.body.appendChild(modal);
    customInput.focus();
  }

  /** FIXED: Safe nested insert + textarea-only .value */
  insertField(field, template) {
    try {
      let json = this.parseEditorJson();
      const path = field.fullPath.split('.');

      let current = json;
      for (let i = 0; i < path.length - 1; i++) {
        const key = path[i];
        if (current[key] === undefined) current[key] = {};
        current = current[key];
      }

      current[path.at(-1)] = template.value ?? null;

      this.updateEditor(json);
      this.showNotification(`✓ Inserted ${field.name}`, 'success');
    } catch (error) {
      console.error('Insert error:', error);
      this.showNotification(`✗ Insert failed: ${error.message}`, 'error');
    }
  }

  /** FIXED: Use ONLY .value for textarea */
  parseEditorJson() {
    try {
      return JSON.parse(this.editor.value);
    } catch {
      return { type: 'cert_profile', version: '0.1' };
    }
  }

  /** FIXED: .value only + focus/scroll */
  updateEditor(json) {
    this.editor.value = JSON.stringify(json, null, 2);
    this.editor.dispatchEvent(new Event('input', { bubbles: true }));
    this.editor.dispatchEvent(new Event('change', { bubbles: true }));
    this.validateJson();
    this.editor.focus();
    this.editor.scrollTop = this.editor.scrollHeight;
  }

  /** FIXED: .value only */
  validateJson() {
    try {
      JSON.parse(this.editor.value);
      this.editor.classList.remove('is-invalid');
      this.editor.classList.add('is-valid');
      const errorEl = document.getElementById('profile_json_error');
      errorEl && (errorEl.textContent = '');
      return true;
    } catch (error) {
      this.editor.classList.remove('is-valid');
      this.editor.classList.add('is-invalid');
      const errorEl = document.getElementById('profile_json_error');
      errorEl && (errorEl.textContent = `Invalid JSON: ${error.message}`);
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
  if (document.getElementById('profile-builder-sidebar')) window.profileBuilder = new CertificateProfileBuilder();
});