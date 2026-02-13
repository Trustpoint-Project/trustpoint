function initializeFieldCatalog() {
  return {
    DATA: {
      label: 'Profile DATA',
      description: 'Global profile settings',
      icon: '',
      fields: [

        { name: 'display_name', fullPath: 'display_name', valueType: 'string', description: 'Friendly name' }
      ]
    },

    SUBJECT: {
      label: 'Subject DN',
      description: 'Distinguished Name attributes',
      icon: '',
      fields: [

        { name: 'Common Name', fullPath: 'subj.common_name', valueType: 'profile_property', description: 'CN (e.g. domain.com)' },
        { name: 'Organization', fullPath: 'subj.organization_name', valueType: 'profile_property', description: 'O (e.g. Company Ltd)' },
        { name: 'Org. Unit', fullPath: 'subj.organizational_unit_name', valueType: 'profile_property', description: 'OU (e.g. IT Dept)' },
        { name: 'Country', fullPath: 'subj.country_name', valueType: 'profile_property', description: 'C (2-letter code)' },
        { name: 'State/Province', fullPath: 'subj.state_or_province_name', valueType: 'profile_property', description: 'ST' },
        { name: 'Locality', fullPath: 'subj.locality_name', valueType: 'profile_property', description: 'L' },
        { name: 'Street Address', fullPath: 'subj.street_address', valueType: 'profile_property', description: 'Street' },
        { name: 'Email', fullPath: 'subj.email_address', valueType: 'profile_property', description: 'Email Address' },
        { name: 'Serial Number', fullPath: 'subj.serial_number', valueType: 'profile_property', description: 'Serial Number' },
        { name: 'Domain Component', fullPath: 'subj.domain_component', valueType: 'profile_property', description: 'DC' },
        { name: 'UID', fullPath: 'subj.uid', valueType: 'profile_property', description: 'User ID' },
        { name: 'Title', fullPath: 'subj.title', valueType: 'profile_property', description: 'Job Title' }
      ]
    },

    EXTENSIONS: {
      label: 'Extensions',
      description: 'X.509 Extensions',
      icon: '',
      fields: [

        { name: 'Key Usage', fullPath: 'ext.key_usage', valueType: 'object', description: 'Key Usage Constraints' },

        { name: 'Digital Signature', fullPath: 'ext.key_usage.digital_signature', valueType: 'boolean', description: 'Auth' },
        { name: 'Content Commitment', fullPath: 'ext.key_usage.content_commitment', valueType: 'boolean', description: 'Non-repudiation' },
        { name: 'Key Encipherment', fullPath: 'ext.key_usage.key_encipherment', valueType: 'boolean', description: 'Encipher keys' },
        { name: 'Data Encipherment', fullPath: 'ext.key_usage.data_encipherment', valueType: 'boolean', description: 'Encipher data' },
        { name: 'Key Agreement', fullPath: 'ext.key_usage.key_agreement', valueType: 'boolean', description: 'Key exchange' },
        { name: 'Key Cert Sign', fullPath: 'ext.key_usage.key_cert_sign', valueType: 'boolean', description: 'Sign certs' },
        { name: 'CRL Sign', fullPath: 'ext.key_usage.crl_sign', valueType: 'boolean', description: 'Sign CRLs' },
        { name: 'Encipher Only', fullPath: 'ext.key_usage.encipher_only', valueType: 'boolean', description: 'Encipher only' },
        { name: 'Decipher Only', fullPath: 'ext.key_usage.decipher_only', valueType: 'boolean', description: 'Decipher only' },
        { name: 'Critical', fullPath: 'ext.key_usage.critical', valueType: 'boolean', description: 'Critical' },

        { name: 'Basic Constraints', fullPath: 'ext.basic_constraints', valueType: 'object', description: 'CA/Path constraints' },
        { name: 'Is CA?', fullPath: 'ext.basic_constraints.ca', valueType: 'boolean', description: 'CA Cert' },
        { name: 'Path Length', fullPath: 'ext.basic_constraints.path_length', valueType: 'number', description: 'Path Depth' },
        { name: 'Critical', fullPath: 'ext.basic_constraints.critical', valueType: 'boolean', description: 'Critical' },

        { name: 'Extended Key Usage', fullPath: 'ext.extended_key_usage', valueType: 'object', description: 'EKU' },
        { name: 'Usages', fullPath: 'ext.extended_key_usage.usages', valueType: 'list', description: 'server_auth, client_auth' },
        { name: 'Critical', fullPath: 'ext.extended_key_usage.critical', valueType: 'boolean', description: 'Critical' },

        { name: 'Subject Alt Name', fullPath: 'ext.subject_alternative_name', valueType: 'object', description: 'SAN' },
        { name: 'DNS', fullPath: 'ext.subject_alternative_name.dns_names', valueType: 'list', description: 'DNS Names' },
        { name: 'IPs', fullPath: 'ext.subject_alternative_name.ip_addresses', valueType: 'list', description: 'IP Addresses' },
        { name: 'Emails', fullPath: 'ext.subject_alternative_name.rfc822_names', valueType: 'list', description: 'Emails' },
        { name: 'URIs', fullPath: 'ext.subject_alternative_name.uris', valueType: 'list', description: 'URIs' },

        { name: 'CRL Dist Points', fullPath: 'ext.crl_distribution_points', valueType: 'object', description: 'CDP' },
        { name: 'URIs', fullPath: 'ext.crl_distribution_points.uris', valueType: 'list', description: 'CRL URLs' }
      ]
    },

    VALIDITY: {
      label: 'Validity',
      description: 'Time constraints',
      icon: '',
      fields: [
        { name: 'Days', fullPath: 'validity.days', valueType: 'number', description: 'Validity in days', suggestions: [30, 90, 365] }      ]
    }
  };
}

window.initializeFieldCatalog = initializeFieldCatalog;