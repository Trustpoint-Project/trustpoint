function initializeFieldCatalog() {
  return {
    DATA: {
      label: 'Profile Data',
      description: 'Global profile settings',
      icon: '',
      fields: [

        { name: 'Display Name', fullPath: 'display_name', valueType: 'string', description: 'Friendly name for the profile' },
        { name: 'Global Reject Mods', fullPath: 'reject_mods', valueType: 'boolean', description: 'Reject unknown top-level fields' }
      ]
    },

    SUBJECT: {
      label: 'Subject DN',
      description: 'Distinguished Name attributes',
      icon: '',
      fields: [
        { name: 'Subj Allow', fullPath: 'subj.allow', valueType: 'list', description: 'Allowed Subject fields (* or list)' },
        { name: 'Subj Reject Mods', fullPath: 'subj.reject_mods', valueType: 'boolean', description: 'Reject unknown Subject fields' },


        { name: 'Common Name', fullPath: 'subj.common_name', aliases: ['subj.cn', 'subj.CN'], valueType: 'profile_property', description: 'CN (e.g. domain.com)' },
        { name: 'Organization', fullPath: 'subj.organization_name', aliases: ['subj.o', 'subj.O'], valueType: 'profile_property', description: 'O (e.g. Company Ltd)' },
        { name: 'Org. Unit', fullPath: 'subj.organizational_unit_name', aliases: ['subj.ou', 'subj.OU'], valueType: 'profile_property', description: 'OU (e.g. IT Dept)' },
        { name: 'Country', fullPath: 'subj.country_name', aliases: ['subj.c', 'subj.C'], valueType: 'profile_property', description: 'C (2-letter code)' },
        { name: 'State/Province', fullPath: 'subj.state_or_province_name', aliases: ['subj.st', 'subj.ST', 'subj.S'], valueType: 'profile_property', description: 'State or Province Name' },
        { name: 'Locality', fullPath: 'subj.locality_name', aliases: ['subj.l', 'subj.L'], valueType: 'profile_property', description: 'Locality (City)' },
        { name: 'Street Address', fullPath: 'subj.street_address', aliases: ['subj.street'], valueType: 'profile_property', description: 'Street Address' },
        { name: 'Email', fullPath: 'subj.email_address', aliases: ['subj.email', 'subj.emailAddress'], valueType: 'profile_property', description: 'Email Address' },
        { name: 'Serial Number', fullPath: 'subj.serial_number', aliases: ['subj.serialNumber', 'subj.sn'], valueType: 'profile_property', description: 'Serial Number' },
        { name: 'Domain Component', fullPath: 'subj.domain_component', aliases: ['subj.dc', 'subj.DC'], valueType: 'profile_property', description: 'Domain Component (DC)' },
        { name: 'UID', fullPath: 'subj.uid', valueType: 'profile_property', description: 'User ID' },
        { name: 'Title', fullPath: 'subj.title', valueType: 'profile_property', description: 'Job Title' }
      ]
    },

    EXTENSIONS: {
      label: 'Extensions',
      description: 'X.509 Extensions',
      icon: '',
      fields: [
        { name: 'Ext Allow', fullPath: 'ext.allow', valueType: 'list', description: 'Allowed Extensions (* or list)' },
        { name: 'Ext Reject Mods', fullPath: 'ext.reject_mods', valueType: 'boolean', description: 'Reject unknown Extensions' },

        { name: 'Key Usage', fullPath: 'ext.key_usage', valueType: 'object', description: 'Key Usage Constraints' },
        { name: 'Digital Signature', fullPath: 'ext.key_usage.digital_signature', valueType: 'boolean', description: 'Usage: Digital Signature (Auth)' },
        { name: 'Content Commitment', fullPath: 'ext.key_usage.content_commitment', valueType: 'boolean', description: 'Usage: Content Commitment (Non-repudiation)' },
        { name: 'Key Encipherment', fullPath: 'ext.key_usage.key_encipherment', valueType: 'boolean', description: 'Usage: Key Encipherment' },
        { name: 'Data Encipherment', fullPath: 'ext.key_usage.data_encipherment', valueType: 'boolean', description: 'Usage: Data Encipherment' },
        { name: 'Key Agreement', fullPath: 'ext.key_usage.key_agreement', valueType: 'boolean', description: 'Usage: Key Agreement' },
        { name: 'Key Cert Sign', fullPath: 'ext.key_usage.key_cert_sign', valueType: 'boolean', description: 'Usage: Key Cert Sign (CA)' },
        { name: 'CRL Sign', fullPath: 'ext.key_usage.crl_sign', valueType: 'boolean', description: 'Usage: CRL Sign' },
        { name: 'Encipher Only', fullPath: 'ext.key_usage.encipher_only', valueType: 'boolean', description: 'Usage: Encipher Only' },
        { name: 'Decipher Only', fullPath: 'ext.key_usage.decipher_only', valueType: 'boolean', description: 'Usage: Decipher Only' },
        { name: 'Critical', fullPath: 'ext.key_usage.critical', valueType: 'boolean', description: 'Mark Key Usage as Critical' },

        { name: 'Basic Constraints', fullPath: 'ext.basic_constraints', valueType: 'object', description: 'Basic Constraints (CA/Path)' },
        { name: 'Is CA?', fullPath: 'ext.basic_constraints.ca', valueType: 'boolean', description: 'Is this certificate a CA?' },
        { name: 'Path Length', fullPath: 'ext.basic_constraints.path_length', valueType: 'number', description: 'Max Path Length' },
        { name: 'Critical', fullPath: 'ext.basic_constraints.critical', valueType: 'boolean', description: 'Mark Basic Constraints as Critical' },

        { name: 'Extended Key Usage', fullPath: 'ext.extended_key_usage', valueType: 'object', description: 'Extended Key Usage (EKU)' },
        { name: 'Usages', fullPath: 'ext.extended_key_usage.usages', valueType: 'list', description: 'List of usages (e.g. server_auth, client_auth)' },
        { name: 'Critical', fullPath: 'ext.extended_key_usage.critical', valueType: 'boolean', description: 'Mark EKU as Critical' },

        { name: 'Subject Alt Name (SAN)', fullPath: 'ext.subject_alternative_name', aliases: ['ext.san', 'ext.SAN'], valueType: 'object', description: 'Subject Alternative Name (SAN), Comma Separated Values' },
        { name: 'SAN Allow', fullPath: 'ext.subject_alternative_name.allow', valueType: 'list', description: 'Allowed SAN types (* or list)' },
        { name: 'DNS', fullPath: 'ext.subject_alternative_name.dns_names', aliases: ['ext.subject_alternative_name.dns'], valueType: 'list', description: 'DNS Names' },
        { name: 'IPs', fullPath: 'ext.subject_alternative_name.ip_addresses', aliases: ['ext.subject_alternative_name.ip'], valueType: 'list', description: 'IP Addresses' },
        { name: 'Emails', fullPath: 'ext.subject_alternative_name.rfc822_names', aliases: ['ext.subject_alternative_name.email', 'ext.subject_alternative_name.rfc822'], valueType: 'list', description: 'RFC822 Names (Emails)' },
        { name: 'URIs', fullPath: 'ext.subject_alternative_name.uris', aliases: ['ext.subject_alternative_name.uri'], valueType: 'list', description: 'Uniform Resource Identifiers (URIs)' },

        { name: 'CRL Dist Points', fullPath: 'ext.crl_distribution_points', valueType: 'object', description: 'CRL Distribution Points' },
        { name: 'URIs', fullPath: 'ext.crl_distribution_points.uris', valueType: 'list', description: 'List of CRL URLs' }
      ]
    },

    VALIDITY: {
      label: 'Validity',
      description: 'Time constraints',
      icon: '',
      fields: [
        { name: 'Days', fullPath: 'validity.days', valueType: 'number', description: 'Validity in days', suggestions: [30, 90, 365] },
      ]
    }
  };
}

window.initializeFieldCatalog = initializeFieldCatalog;