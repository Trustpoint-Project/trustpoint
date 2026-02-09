// static/js/fields-catalog.js

function initializeFieldCatalog() {
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

// expose globally for non-module usage
window.initializeFieldCatalog = initializeFieldCatalog;
