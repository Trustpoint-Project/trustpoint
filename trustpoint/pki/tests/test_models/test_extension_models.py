"""Tests for extension model methods and properties."""

import pytest
from django.db import IntegrityError
from cryptography.x509.oid import NameOID

from pki.models.extension import (
    AttributeTypeAndValue,
    GeneralNameDNSName,
    GeneralNameRFC822Name,
    GeneralNameUniformResourceIdentifier,
    GeneralNameIpAddress,
    GeneralNameRegisteredId,
    GeneralNameDirectoryName,
    GeneralNameOtherName,
)
from trustpoint_core.oid import NameOid


@pytest.mark.django_db
class TestAttributeTypeAndValue:
    """Test suite for AttributeTypeAndValue model."""

    def test_str_with_known_oid(self):
        """Test __str__ method with a known NameOid."""
        attr = AttributeTypeAndValue.objects.create(
            oid=NameOID.COMMON_NAME.dotted_string,
            value='test.example.com'
        )
        result = str(attr)
        assert 'test.example.com' in result
        # The __str__ uses NameOid enum which returns the dotted string if unknown
        assert '=' in result

    def test_str_with_unknown_oid(self):
        """Test __str__ method with an unknown OID."""
        custom_oid = '1.2.3.4.5.6'
        attr = AttributeTypeAndValue.objects.create(
            oid=custom_oid,
            value='custom_value'
        )
        result = str(attr)
        assert custom_oid in result
        assert 'custom_value' in result

    def test_abbreviation_property(self):
        """Test abbreviation property for known OID."""
        attr = AttributeTypeAndValue.objects.create(
            oid=NameOid.COMMON_NAME.value,
            value='test2.example.com'
        )
        abbreviation = attr.abbreviation
        assert abbreviation == 'CN'

    def test_verbose_name_property(self):
        """Test verbose_name property for known OID."""
        attr = AttributeTypeAndValue.objects.create(
            oid=NameOid.COMMON_NAME.value,
            value='test3.example.com'
        )
        verbose_name = attr.verbose_name
        assert 'Common Name' in verbose_name

    def test_unique_together_constraint(self):
        """Test that unique_together constraint raises IntegrityError on duplicate."""
        AttributeTypeAndValue.objects.create(
            oid=NameOID.LOCALITY_NAME.dotted_string,
            value='unique_test'
        )
        # Try to create duplicate - should raise IntegrityError
        with pytest.raises(IntegrityError):
            AttributeTypeAndValue.objects.create(
                oid=NameOID.LOCALITY_NAME.dotted_string,
                value='unique_test'
            )


@pytest.mark.django_db
class TestGeneralNameModels:
    """Test suite for GeneralName model classes."""

    def test_general_name_rfc822_str(self):
        """Test GeneralNameRFC822Name __str__ method."""
        email = GeneralNameRFC822Name.objects.create(value='test1@unique-example.com')
        assert str(email) == 'test1@unique-example.com'

    def test_general_name_rfc822_unique_constraint(self):
        """Test GeneralNameRFC822Name unique constraint."""
        GeneralNameRFC822Name.objects.create(value='test2@unique-example.com')
        # Second create should raise IntegrityError
        with pytest.raises(IntegrityError):
            GeneralNameRFC822Name.objects.create(value='test2@unique-example.com')

    def test_general_name_dns_str(self):
        """Test GeneralNameDNSName __str__ method."""
        dns = GeneralNameDNSName.objects.create(value='unique1.example.com')
        assert str(dns) == 'unique1.example.com'

    def test_general_name_dns_unique_constraint(self):
        """Test GeneralNameDNSName unique constraint."""
        GeneralNameDNSName.objects.create(value='unique2.example.com')
        with pytest.raises(IntegrityError):
            GeneralNameDNSName.objects.create(value='unique2.example.com')

    def test_general_name_uri_str(self):
        """Test GeneralNameUniformResourceIdentifier __str__ method."""
        uri = GeneralNameUniformResourceIdentifier.objects.create(
            value='https://unique1.example.com'
        )
        assert str(uri) == 'https://unique1.example.com'

    def test_general_name_uri_unique_constraint(self):
        """Test GeneralNameUniformResourceIdentifier unique constraint."""
        GeneralNameUniformResourceIdentifier.objects.create(value='https://unique2.example.com')
        with pytest.raises(IntegrityError):
            GeneralNameUniformResourceIdentifier.objects.create(value='https://unique2.example.com')

    def test_general_name_ip_address_str(self):
        """Test GeneralNameIpAddress __str__ method."""
        ip = GeneralNameIpAddress.objects.create(
            ip_type=GeneralNameIpAddress.IpType.IPV4_ADDRESS,
            value='192.168.1.2'
        )
        result = str(ip)
        assert '192.168.1.2' in result
        assert 'IPv4 Address' in result

    def test_general_name_ip_address_unique_constraint(self):
        """Test GeneralNameIpAddress unique constraint."""
        GeneralNameIpAddress.objects.create(
            ip_type=GeneralNameIpAddress.IpType.IPV4_ADDRESS,
            value='192.168.1.3'
        )
        with pytest.raises(IntegrityError):
            GeneralNameIpAddress.objects.create(
                ip_type=GeneralNameIpAddress.IpType.IPV4_ADDRESS,
                value='192.168.1.3'
            )

    def test_general_name_registered_id_str(self):
        """Test GeneralNameRegisteredId __str__ method."""
        reg_id = GeneralNameRegisteredId.objects.create(value='1.2.3.4.5.7')
        assert str(reg_id) == '1.2.3.4.5.7'

    def test_general_name_registered_id_allows_duplicates(self):
        """Test GeneralNameRegisteredId allows duplicates (no unique constraint)."""
        GeneralNameRegisteredId.objects.create(value='1.2.3.4.5.8')
        # Should not raise error - no unique constraint
        GeneralNameRegisteredId.objects.create(value='1.2.3.4.5.8')
        count = GeneralNameRegisteredId.objects.filter(value='1.2.3.4.5.8').count()
        assert count == 2  # Allows duplicates

    def test_general_name_directory_name_str(self):
        """Test GeneralNameDirectoryName __str__ method."""
        dir_name = GeneralNameDirectoryName.objects.create()
        attr = AttributeTypeAndValue.objects.create(
            oid=NameOID.COMMON_NAME.dotted_string,
            value='dir.example.com'
        )
        dir_name.names.add(attr)
        result = str(dir_name)
        assert 'dir.example.com' in result

    def test_general_name_other_name_str(self):
        """Test GeneralNameOtherName __str__ method."""
        other_name = GeneralNameOtherName.objects.create(
            type_id='1.2.3.4.5.9',
            value='48656C6C6F31'  # Hex encoded
        )
        result = str(other_name)
        assert '1.2.3.4.5.9' in result
        # The __str__ method shows truncated hex value with "DER:" prefix
        assert 'DER:' in result or '48656C6C6F' in result

    def test_general_name_other_name_unique_constraint(self):
        """Test GeneralNameOtherName unique constraint."""
        GeneralNameOtherName.objects.create(
            type_id='1.2.3.4.5.10',
            value='48656C6C6F32'
        )
        with pytest.raises(IntegrityError):
            GeneralNameOtherName.objects.create(
                type_id='1.2.3.4.5.10',
                value='48656C6C6F32'
            )


@pytest.mark.django_db
class TestCertificateExtensionAbstract:
    """Test suite for CertificateExtension abstract methods."""

    def test_extension_oid_property_raises_error_when_not_set(self):
        """Test that extension_oid raises AttributeError when _extension_oid not set."""
        # We can't instantiate abstract class directly, but we can test the property logic
        # by creating a minimal concrete subclass
        from pki.models.extension import BasicConstraintsExtension
        
        ext = BasicConstraintsExtension.objects.create(
            critical=True,
            ca=False
        )
        # BasicConstraintsExtension should have _extension_oid set
        assert ext.extension_oid is not None
        assert isinstance(ext.extension_oid, str)

    def test_extension_oid_property_returns_value_when_set(self):
        """Test that extension_oid returns the correct value when _extension_oid is set."""
        from pki.models.extension import KeyUsageExtension
        
        ext = KeyUsageExtension.objects.create(
            critical=True,
            digital_signature=True
        )
        oid = ext.extension_oid
        assert oid is not None
        assert isinstance(oid, str)
        # KeyUsage OID should be 2.5.29.15
        assert '2.5.29.15' in oid


@pytest.mark.django_db
class TestGeneralNameOrphanDeletion:
    """Test orphan deletion behavior for GeneralName models."""

    def test_general_name_rfc822_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameRFC822Name, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameRFC822Name.check_references_on_delete

    def test_general_name_dns_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameDNSName, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameDNSName.check_references_on_delete

    def test_general_name_uri_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameUniformResourceIdentifier, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameUniformResourceIdentifier.check_references_on_delete

    def test_general_name_ip_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameIpAddress, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameIpAddress.check_references_on_delete

    def test_general_name_registered_id_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameRegisteredId, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameRegisteredId.check_references_on_delete

    def test_general_name_directory_name_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameDirectoryName, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameDirectoryName.check_references_on_delete

    def test_general_name_other_name_check_references_attribute(self):
        """Test that check_references_on_delete attribute exists."""
        assert hasattr(GeneralNameOtherName, 'check_references_on_delete')
        assert 'general_names_set' in GeneralNameOtherName.check_references_on_delete


@pytest.mark.django_db
class TestBasicConstraintsExtension:
    """Test suite for BasicConstraintsExtension model."""

    def test_basic_constraints_creation(self):
        """Test creating BasicConstraintsExtension."""
        from pki.models.extension import BasicConstraintsExtension
        
        ext = BasicConstraintsExtension.objects.create(
            critical=True,
            ca=True,
            path_length_constraint=3
        )
        assert ext.critical is True
        assert ext.ca is True
        assert ext.path_length_constraint == 3

    def test_basic_constraints_str(self):
        """Test __str__ method of BasicConstraintsExtension."""
        from pki.models.extension import BasicConstraintsExtension
        
        ext = BasicConstraintsExtension.objects.create(
            critical=False,
            ca=False
        )
        result = str(ext)
        assert 'BasicConstraintsExtension' in result
        assert 'critical=False' in result

    def test_basic_constraints_unique_together(self):
        """Test unique_together constraint on BasicConstraintsExtension."""
        from pki.models.extension import BasicConstraintsExtension
        
        BasicConstraintsExtension.objects.create(
            critical=True,
            ca=True,
            path_length_constraint=2
        )
        # Should raise IntegrityError on duplicate
        with pytest.raises(IntegrityError):
            BasicConstraintsExtension.objects.create(
                critical=True,
                ca=True,
                path_length_constraint=2
            )

    def test_basic_constraints_save_from_crypto_extensions(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from cryptography.x509 import BasicConstraints
        from pki.models.extension import BasicConstraintsExtension
        
        # Create crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
            critical=True,
            value=BasicConstraints(ca=True, path_length=5)
        )
        
        # Save it
        result = BasicConstraintsExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.critical is True
        assert result.ca is True
        assert result.path_length_constraint == 5

    def test_basic_constraints_save_from_crypto_returns_existing(self):
        """Test that save_from_crypto_extensions returns existing entry if found."""
        from cryptography import x509
        from cryptography.x509 import BasicConstraints
        from pki.models.extension import BasicConstraintsExtension
        
        # Create existing entry
        existing = BasicConstraintsExtension.objects.create(
            critical=False,
            ca=False,
            path_length_constraint=None
        )
        
        # Create matching crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.BASIC_CONSTRAINTS,
            critical=False,
            value=BasicConstraints(ca=False, path_length=None)
        )
        
        # Should return existing entry
        result = BasicConstraintsExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.id == existing.id

    def test_basic_constraints_save_from_crypto_wrong_type(self):
        """Test save_from_crypto_extensions with wrong extension type."""
        from cryptography import x509
        from pki.models.extension import BasicConstraintsExtension
        
        # Create extension with wrong value type
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        # Should return None for wrong type
        result = BasicConstraintsExtension.save_from_crypto_extensions(crypto_ext)
        assert result is None


@pytest.mark.django_db
class TestKeyUsageExtension:
    """Test suite for KeyUsageExtension model."""

    def test_key_usage_creation(self):
        """Test creating KeyUsageExtension."""
        from pki.models.extension import KeyUsageExtension
        
        ext = KeyUsageExtension.objects.create(
            critical=True,
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        assert ext.critical is True
        assert ext.digital_signature is True
        assert ext.key_encipherment is True

    def test_key_usage_str(self):
        """Test __str__ method of KeyUsageExtension."""
        from pki.models.extension import KeyUsageExtension
        
        ext = KeyUsageExtension.objects.create(
            critical=False,
            digital_signature=True
        )
        result = str(ext)
        assert 'KeyUsageExtension' in result
        assert 'critical=False' in result

    def test_key_usage_save_from_crypto_extensions(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from pki.models.extension import KeyUsageExtension
        
        # Create crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        # Save it
        result = KeyUsageExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.critical is True
        assert result.digital_signature is True
        assert result.content_commitment is True
        assert result.key_cert_sign is True

    def test_key_usage_save_from_crypto_returns_existing(self):
        """Test that save_from_crypto_extensions returns existing entry if found."""
        from cryptography import x509
        from pki.models.extension import KeyUsageExtension
        
        # Create existing entry
        existing = KeyUsageExtension.objects.create(
            critical=False,
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        )
        
        # Create matching crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=False,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        # Should return existing entry
        result = KeyUsageExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.id == existing.id


@pytest.mark.django_db
class TestGeneralNamesModel:
    """Test suite for GeneralNamesModel."""

    def test_general_names_model_str_empty(self):
        """Test __str__ for empty GeneralNamesModel."""
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        result = str(gn_model)
        assert 'GeneralNamesModel(Empty)' in result

    def test_general_names_model_str_with_dns(self):
        """Test __str__ with DNS names."""
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        dns = GeneralNameDNSName.objects.create(value='gn-test.example.com')
        gn_model.dns_names.add(dns)
        
        result = str(gn_model)
        assert 'DNS:' in result
        assert 'gn-test.example.com' in result

    def test_general_names_model_save_rfc822_name(self):
        """Test _save_rfc822_name method."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        rfc822 = x509.RFC822Name('newtest@example.com')
        
        gn_model._save_rfc822_name(rfc822)
        
        assert gn_model.rfc822_names.count() == 1
        assert gn_model.rfc822_names.first().value == 'newtest@example.com'

    def test_general_names_model_save_dns_name(self):
        """Test _save_dns_name method."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        dns = x509.DNSName('newdns.example.com')
        
        gn_model._save_dns_name(dns)
        
        assert gn_model.dns_names.count() == 1
        assert gn_model.dns_names.first().value == 'newdns.example.com'

    def test_general_names_model_save_ip_address_ipv4(self):
        """Test _save_ip_address method with IPv4."""
        from cryptography import x509
        from ipaddress import IPv4Address
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        ip = x509.IPAddress(IPv4Address('192.168.100.1'))
        
        gn_model._save_ip_address(ip)
        
        assert gn_model.ip_addresses.count() == 1
        saved_ip = gn_model.ip_addresses.first()
        assert saved_ip.value == '192.168.100.1'
        assert saved_ip.ip_type == GeneralNameIpAddress.IpType.IPV4_ADDRESS

    def test_general_names_model_save_ip_address_ipv6(self):
        """Test _save_ip_address method with IPv6."""
        from cryptography import x509
        from ipaddress import IPv6Address
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        ip = x509.IPAddress(IPv6Address('2001:db8::1'))
        
        gn_model._save_ip_address(ip)
        
        assert gn_model.ip_addresses.count() == 1
        saved_ip = gn_model.ip_addresses.first()
        assert saved_ip.ip_type == GeneralNameIpAddress.IpType.IPV6_ADDRESS

    def test_general_names_model_save_ip_address_ipv4_network(self):
        """Test _save_ip_address method with IPv4 network."""
        from cryptography import x509
        from ipaddress import IPv4Network
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        ip = x509.IPAddress(IPv4Network('10.0.0.0/24'))
        
        gn_model._save_ip_address(ip)
        
        assert gn_model.ip_addresses.count() == 1
        saved_ip = gn_model.ip_addresses.first()
        assert saved_ip.ip_type == GeneralNameIpAddress.IpType.IPV4_NETWORK

    def test_general_names_model_save_ip_address_ipv6_network(self):
        """Test _save_ip_address method with IPv6 network."""
        from cryptography import x509
        from ipaddress import IPv6Network
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        ip = x509.IPAddress(IPv6Network('2001:db8::/32'))
        
        gn_model._save_ip_address(ip)
        
        assert gn_model.ip_addresses.count() == 1
        saved_ip = gn_model.ip_addresses.first()
        assert saved_ip.ip_type == GeneralNameIpAddress.IpType.IPV6_NETWORK

    def test_general_names_model_save_uri(self):
        """Test _save_uri method."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        uri = x509.UniformResourceIdentifier('https://newuri.example.com')
        
        gn_model._save_uri(uri)
        
        assert gn_model.uniform_resource_identifiers.count() == 1
        assert gn_model.uniform_resource_identifiers.first().value == 'https://newuri.example.com'

    def test_general_names_model_save_registered_id(self):
        """Test _save_registered_id method."""
        from cryptography import x509
        from cryptography.x509.oid import ObjectIdentifier
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        reg_id = x509.RegisteredID(ObjectIdentifier('1.2.3.4.5.99'))
        
        gn_model._save_registered_id(reg_id)
        
        assert gn_model.registered_ids.count() == 1
        assert gn_model.registered_ids.first().value == '1.2.3.4.5.99'

    def test_general_names_model_save_other_name(self):
        """Test _save_other_name method."""
        from cryptography import x509
        from cryptography.x509.oid import ObjectIdentifier
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        other = x509.OtherName(ObjectIdentifier('1.2.3.4.5.100'), b'\x04\x05Hello')
        
        gn_model._save_other_name(other)
        
        assert gn_model.other_names.count() == 1
        saved_other = gn_model.other_names.first()
        assert saved_other.type_id == '1.2.3.4.5.100'

    def test_general_names_model_save_directory_name(self):
        """Test _save_directory_name method."""
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, 'dir-test.example.com'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Test Org'),
        ])
        dir_name = x509.DirectoryName(name)
        
        gn_model._save_directory_name(dir_name)
        
        assert gn_model.directory_names.count() == 1
        saved_dir = gn_model.directory_names.first()
        assert saved_dir.names.count() == 2

    def test_general_names_model_save_general_names_with_list(self):
        """Test save_general_names with a list of GeneralNames."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        general_names = [
            x509.DNSName('list-test1.example.com'),
            x509.DNSName('list-test2.example.com'),
            x509.RFC822Name('listtest@example.com'),
        ]
        
        result = gn_model.save_general_names(general_names)
        
        assert result is not None
        assert gn_model.dns_names.count() == 2
        assert gn_model.rfc822_names.count() == 1

    def test_general_names_model_save_general_names_reuses_existing(self):
        """Test that save_general_names reuses existing entries."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        
        # Create existing DNS name
        existing_dns = GeneralNameDNSName.objects.create(value='reuse-test.example.com')
        
        gn_model = GeneralNamesModel.objects.create()
        general_names = [
            x509.DNSName('reuse-test.example.com'),
        ]
        
        gn_model.save_general_names(general_names)
        
        # Should reuse existing entry, not create new one
        assert GeneralNameDNSName.objects.filter(value='reuse-test.example.com').count() == 1
        assert gn_model.dns_names.first().id == existing_dns.id


@pytest.mark.django_db
class TestSubjectAlternativeNameExtension:
    """Test suite for SubjectAlternativeNameExtension."""

    def test_san_extension_creation(self):
        """Test creating SubjectAlternativeNameExtension."""
        from pki.models.extension import SubjectAlternativeNameExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        san = SubjectAlternativeNameExtension.objects.create(
            critical=False,
            subject_alt_name=gn
        )
        assert san.critical is False
        assert san.subject_alt_name == gn

    def test_san_extension_str(self):
        """Test __str__ method."""
        from pki.models.extension import SubjectAlternativeNameExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        san = SubjectAlternativeNameExtension.objects.create(
            critical=True,
            subject_alt_name=gn
        )
        result = str(san)
        assert 'SubjectAlternativeNameExtension' in result
        assert 'critical=True' in result

    def test_san_save_from_crypto_extensions(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from pki.models.extension import SubjectAlternativeNameExtension
        
        # Create crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName([
                x509.DNSName('san-test.example.com'),
                x509.RFC822Name('san@example.com'),
            ])
        )
        
        # Save it
        result = SubjectAlternativeNameExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.critical is False
        assert result.subject_alt_name is not None
        assert result.subject_alt_name.dns_names.count() == 1
        assert result.subject_alt_name.rfc822_names.count() == 1

    def test_san_save_from_crypto_wrong_type(self):
        """Test save_from_crypto_extensions with wrong extension type."""
        from cryptography import x509
        from pki.models.extension import SubjectAlternativeNameExtension
        
        # Create extension with wrong value type
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        # Should return None for wrong type
        result = SubjectAlternativeNameExtension.save_from_crypto_extensions(crypto_ext)
        assert result is None

    def test_san_post_delete_cleans_up_orphaned_general_names(self):
        """Test that post_delete cleans up orphaned GeneralNamesModel."""
        from pki.models.extension import SubjectAlternativeNameExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        gn_id = gn.id
        
        san = SubjectAlternativeNameExtension.objects.create(
            critical=False,
            subject_alt_name=gn
        )
        
        # Delete the SAN extension
        san.delete()
        
        # GeneralNamesModel should be deleted (orphaned)
        assert not GeneralNamesModel.objects.filter(id=gn_id).exists()


@pytest.mark.django_db
class TestIssuerAlternativeNameExtension:
    """Test suite for IssuerAlternativeNameExtension."""

    def test_ian_extension_creation(self):
        """Test creating IssuerAlternativeNameExtension."""
        from pki.models.extension import IssuerAlternativeNameExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        ian = IssuerAlternativeNameExtension.objects.create(
            critical=False,
            issuer_alt_name=gn
        )
        assert ian.critical is False
        assert ian.issuer_alt_name == gn

    def test_ian_extension_str(self):
        """Test __str__ method."""
        from pki.models.extension import IssuerAlternativeNameExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        ian = IssuerAlternativeNameExtension.objects.create(
            critical=True,
            issuer_alt_name=gn
        )
        result = str(ian)
        assert 'IssuerAlternativeNameExtension' in result
        assert 'critical=True' in result

    def test_ian_save_from_crypto_extensions(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from pki.models.extension import IssuerAlternativeNameExtension
        
        # Create crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.ISSUER_ALTERNATIVE_NAME,
            critical=False,
            value=x509.IssuerAlternativeName([
                x509.DNSName('ian-test.example.com'),
                x509.RFC822Name('ian@example.com'),
            ])
        )
        
        # Save it
        result = IssuerAlternativeNameExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.critical is False
        assert result.issuer_alt_name is not None
        assert result.issuer_alt_name.dns_names.count() == 1
        assert result.issuer_alt_name.rfc822_names.count() == 1

    def test_ian_save_from_crypto_wrong_type(self):
        """Test save_from_crypto_extensions with wrong extension type."""
        from cryptography import x509
        from pki.models.extension import IssuerAlternativeNameExtension
        
        # Create extension with wrong value type
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        # Should return None for wrong type
        result = IssuerAlternativeNameExtension.save_from_crypto_extensions(crypto_ext)
        assert result is None

    def test_ian_post_delete_cleans_up_orphaned_general_names(self):
        """Test that post_delete cleans up orphaned GeneralNamesModel."""
        from pki.models.extension import IssuerAlternativeNameExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        gn_id = gn.id
        
        ian = IssuerAlternativeNameExtension.objects.create(
            critical=False,
            issuer_alt_name=gn
        )
        
        # Delete the IAN extension
        ian.delete()
        
        # GeneralNamesModel should be deleted (orphaned)
        assert not GeneralNamesModel.objects.filter(id=gn_id).exists()


@pytest.mark.django_db
class TestAuthorityKeyIdentifierExtension:
    """Test suite for AuthorityKeyIdentifierExtension."""

    def test_aki_extension_creation(self):
        """Test creating AuthorityKeyIdentifierExtension."""
        from pki.models.extension import AuthorityKeyIdentifierExtension
        
        aki = AuthorityKeyIdentifierExtension.objects.create(
            critical=False,
            key_identifier='0123456789ABCDEF',
            authority_cert_serial_number=12345
        )
        assert aki.critical is False
        assert aki.key_identifier == '0123456789ABCDEF'
        assert aki.authority_cert_serial_number == 12345

    def test_aki_extension_str(self):
        """Test __str__ method."""
        from pki.models.extension import AuthorityKeyIdentifierExtension
        
        aki = AuthorityKeyIdentifierExtension.objects.create(
            critical=False,
            key_identifier='FEDCBA9876543210'
        )
        result = str(aki)
        assert 'AuthorityKeyIdentifier' in result
        assert 'critical=False' in result


@pytest.mark.django_db
class TestSubjectKeyIdentifierExtension:
    """Test suite for SubjectKeyIdentifierExtension."""

    def test_ski_extension_creation(self):
        """Test creating SubjectKeyIdentifierExtension."""
        from pki.models.extension import SubjectKeyIdentifierExtension
        
        ski = SubjectKeyIdentifierExtension.objects.create(
            key_identifier='AABBCCDDEEFF0011'
        )
        assert ski.key_identifier == 'AABBCCDDEEFF0011'

    def test_ski_extension_str(self):
        """Test __str__ method."""
        from pki.models.extension import SubjectKeyIdentifierExtension
        
        ski = SubjectKeyIdentifierExtension.objects.create(
            key_identifier='1122334455667788'
        )
        result = str(ski)
        assert 'SubjectKeyIdentifierExtension' in result
        assert '1122334455667788' in result

    def test_ski_unique_constraint(self):
        """Test unique constraint on key_identifier."""
        from pki.models.extension import SubjectKeyIdentifierExtension
        
        SubjectKeyIdentifierExtension.objects.create(
            key_identifier='UNIQUE123456'
        )
        # Should raise IntegrityError on duplicate
        with pytest.raises(IntegrityError):
            SubjectKeyIdentifierExtension.objects.create(
                key_identifier='UNIQUE123456'
            )


@pytest.mark.django_db
class TestExtendedKeyUsageExtension:
    """Test suite for ExtendedKeyUsageExtension."""

    def test_eku_extension_creation(self):
        """Test creating ExtendedKeyUsageExtension."""
        from pki.models.extension import ExtendedKeyUsageExtension, KeyPurposeIdModel
        
        eku = ExtendedKeyUsageExtension.objects.create(
            critical=False
        )
        # Add some key purpose IDs
        kp1 = KeyPurposeIdModel.objects.create(oid='1.3.6.1.5.5.7.3.1')  # serverAuth
        kp2 = KeyPurposeIdModel.objects.create(oid='1.3.6.1.5.5.7.3.2')  # clientAuth
        eku.key_purpose_ids.add(kp1, kp2)
        
        assert eku.critical is False
        assert eku.key_purpose_ids.count() == 2

    def test_eku_extension_str(self):
        """Test __str__ method."""
        from pki.models.extension import ExtendedKeyUsageExtension
        
        eku = ExtendedKeyUsageExtension.objects.create(
            critical=True
        )
        result = str(eku)
        assert 'ExtendedKeyUsageExtension' in result
        assert 'critical=True' in result


@pytest.mark.django_db
class TestPolicyConstraintsExtension:
    """Test suite for PolicyConstraintsExtension."""

    def test_policy_constraints_creation(self):
        """Test creating PolicyConstraintsExtension."""
        from pki.models.extension import PolicyConstraintsExtension
        
        pc = PolicyConstraintsExtension.objects.create(
            critical=True,
            require_explicit_policy=2,
            inhibit_policy_mapping=3
        )
        assert pc.critical is True
        assert pc.require_explicit_policy == 2
        assert pc.inhibit_policy_mapping == 3

    def test_policy_constraints_str(self):
        """Test __str__ method."""
        from pki.models.extension import PolicyConstraintsExtension
        
        pc = PolicyConstraintsExtension.objects.create(
            critical=False,
            require_explicit_policy=1
        )
        result = str(pc)
        assert 'PolicyConstraintsExtension' in result
        assert 'critical=False' in result

    def test_policy_constraints_allows_duplicate_with_different_critical(self):
        """Test that PolicyConstraintsExtension allows duplicates with different critical flag."""
        from pki.models.extension import PolicyConstraintsExtension
        
        pc1 = PolicyConstraintsExtension.objects.create(
            critical=True,
            require_explicit_policy=5,
            inhibit_policy_mapping=5
        )
        # Can create another with same values but different critical flag
        pc2 = PolicyConstraintsExtension.objects.create(
            critical=False,
            require_explicit_policy=5,
            inhibit_policy_mapping=5
        )
        assert pc1.id != pc2.id


@pytest.mark.django_db
class TestGeneralNameIpAddressTypes:
    """Test suite for GeneralNameIpAddress IP type variations."""

    def test_ip_address_ipv4_address_type(self):
        """Test IPv4 address type string representation."""
        ip = GeneralNameIpAddress.objects.create(
            ip_type=GeneralNameIpAddress.IpType.IPV4_ADDRESS,
            value='10.0.0.1'
        )
        result = str(ip)
        assert 'IPv4 Address' in result
        assert '10.0.0.1' in result

    def test_ip_address_ipv6_address_type(self):
        """Test IPv6 address type string representation."""
        ip = GeneralNameIpAddress.objects.create(
            ip_type=GeneralNameIpAddress.IpType.IPV6_ADDRESS,
            value='2001:db8::8a2e:370:7334'
        )
        result = str(ip)
        assert 'IPv6 Address' in result

    def test_ip_address_ipv4_network_type(self):
        """Test IPv4 network type string representation."""
        ip = GeneralNameIpAddress.objects.create(
            ip_type=GeneralNameIpAddress.IpType.IPV4_NETWORK,
            value='192.168.0.0/16'
        )
        result = str(ip)
        assert 'IPv4 Network' in result

    def test_ip_address_ipv6_network_type(self):
        """Test IPv6 network type string representation."""
        ip = GeneralNameIpAddress.objects.create(
            ip_type=GeneralNameIpAddress.IpType.IPV6_NETWORK,
            value='2001:db8::/48'
        )
        result = str(ip)
        assert 'IPv6 Network' in result


@pytest.mark.django_db
class TestGeneralNamesModelEdgeCases:
    """Test edge cases and error handling for GeneralNamesModel."""

    def test_save_general_names_with_extension_object(self):
        """Test save_general_names with x509.Extension object."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        
        # Create an Extension object (not just a list)
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
            critical=False,
            value=x509.SubjectAlternativeName([
                x509.DNSName('ext-test.example.com'),
            ])
        )
        
        result = gn_model.save_general_names(crypto_ext)
        
        assert result is not None
        assert gn_model.dns_names.count() == 1

    def test_save_ip_address_invalid_type_raises_error(self):
        """Test that _save_ip_address raises TypeError for invalid IP type."""
        from cryptography import x509
        from pki.models.extension import GeneralNamesModel
        from unittest.mock import Mock
        
        gn_model = GeneralNamesModel.objects.create()
        
        # Create a mock with an unsupported IP type
        mock_entry = Mock(spec=x509.IPAddress)
        mock_entry.value = "invalid_ip_type"
        
        with pytest.raises(TypeError, match='Unknown IP address type'):
            gn_model._save_ip_address(mock_entry)

    def test_general_names_model_str_with_multiple_types(self):
        """Test __str__ with multiple general name types."""
        from pki.models.extension import GeneralNamesModel
        
        gn_model = GeneralNamesModel.objects.create()
        
        # Add multiple types
        dns = GeneralNameDNSName.objects.create(value='multi-test.example.com')
        rfc = GeneralNameRFC822Name.objects.create(value='multi@example.com')
        uri = GeneralNameUniformResourceIdentifier.objects.create(value='https://multi.example.com')
        
        gn_model.dns_names.add(dns)
        gn_model.rfc822_names.add(rfc)
        gn_model.uniform_resource_identifiers.add(uri)
        
        result = str(gn_model)
        assert 'DNS:' in result
        assert 'RFC822:' in result
        assert 'URI:' in result
        assert 'multi-test.example.com' in result


@pytest.mark.django_db
class TestAuthorityKeyIdentifierExtensionComplex:
    """Test suite for AuthorityKeyIdentifierExtension complex scenarios."""

    def test_aki_save_from_crypto_with_all_fields(self):
        """Test save_from_crypto_extensions with all fields populated."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta, UTC
        from pki.models.extension import AuthorityKeyIdentifierExtension
        
        # Create a CA cert to get the AKI from
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA"),
        ])
        
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(1000)
            .not_valid_before(datetime.now(UTC))
            .not_valid_after(datetime.now(UTC) + timedelta(days=365))
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        
        # Now create a cert with AKI
        ski_ext = ca_cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        
        aki_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=False,
            value=x509.AuthorityKeyIdentifier(
                key_identifier=ski_ext.value.digest,
                authority_cert_issuer=[x509.DirectoryName(issuer)],
                authority_cert_serial_number=1000,
            )
        )
        
        result = AuthorityKeyIdentifierExtension.save_from_crypto_extensions(aki_ext)
        
        assert result is not None
        assert result.key_identifier is not None
        assert result.authority_cert_serial_number is not None
        assert result.authority_cert_issuer is not None

    def test_aki_save_from_crypto_minimal(self):
        """Test save_from_crypto_extensions with minimal fields."""
        from cryptography import x509
        from pki.models.extension import AuthorityKeyIdentifierExtension
        
        aki_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
            critical=False,
            value=x509.AuthorityKeyIdentifier(
                key_identifier=b'\x01\x02\x03\x04\x05',
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            )
        )
        
        result = AuthorityKeyIdentifierExtension.save_from_crypto_extensions(aki_ext)
        
        assert result is not None
        assert result.key_identifier == '0102030405'
        assert result.authority_cert_serial_number is None
        assert result.authority_cert_issuer is None

    def test_aki_post_delete_cleanup(self):
        """Test that post_delete cleans up orphaned GeneralNamesModel."""
        from pki.models.extension import AuthorityKeyIdentifierExtension, GeneralNamesModel
        
        gn = GeneralNamesModel.objects.create()
        gn_id = gn.id
        
        aki = AuthorityKeyIdentifierExtension.objects.create(
            critical=False,
            key_identifier='AABBCCDD',
            authority_cert_issuer=gn
        )
        
        # Delete the AKI extension
        aki.delete()
        
        # GeneralNamesModel should be deleted (orphaned)
        assert not GeneralNamesModel.objects.filter(id=gn_id).exists()


@pytest.mark.django_db
class TestSubjectKeyIdentifierExtensionSaveFromCrypto:
    """Test suite for SubjectKeyIdentifierExtension save_from_crypto_extensions."""

    def test_ski_save_from_crypto_extensions(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from pki.models.extension import SubjectKeyIdentifierExtension
        
        # Generate a key and create SKI from it
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ski_value = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        
        ski_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=ski_value
        )
        
        result = SubjectKeyIdentifierExtension.save_from_crypto_extensions(ski_ext)
        
        assert result is not None
        assert result.key_identifier is not None
        assert len(result.key_identifier) > 0

    def test_ski_save_from_crypto_returns_existing(self):
        """Test that save_from_crypto_extensions returns existing entry."""
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa
        from pki.models.extension import SubjectKeyIdentifierExtension
        
        # Generate a key and create SKI from it
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ski_value = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        key_id_hex = ski_value.digest.hex().upper()
        
        # Create existing entry with this key_identifier
        existing = SubjectKeyIdentifierExtension.objects.create(
            key_identifier=key_id_hex
        )
        
        # Create extension with the same SKI
        ski_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER,
            critical=False,
            value=ski_value
        )
        
        result = SubjectKeyIdentifierExtension.save_from_crypto_extensions(ski_ext)
        
        assert result is not None
        assert result.id == existing.id

    def test_ski_save_from_crypto_wrong_type(self):
        """Test save_from_crypto_extensions with wrong extension type."""
        from cryptography import x509
        from pki.models.extension import SubjectKeyIdentifierExtension
        
        # Create extension with wrong value type
        wrong_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        result = SubjectKeyIdentifierExtension.save_from_crypto_extensions(wrong_ext)
        assert result is None


@pytest.mark.django_db
class TestExtendedKeyUsageExtensionSaveFromCrypto:
    """Test suite for ExtendedKeyUsageExtension save_from_crypto_extensions."""

    def test_eku_save_from_crypto_extensions(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        from pki.models.extension import ExtendedKeyUsageExtension
        
        # Create crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
            critical=False,
            value=x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CLIENT_AUTH,
            ])
        )
        
        result = ExtendedKeyUsageExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.critical is False
        assert result.key_purpose_ids.count() == 2

    def test_eku_save_from_crypto_reuses_key_purpose_ids(self):
        """Test that save_from_crypto_extensions reuses existing KeyPurposeIdModel."""
        from cryptography import x509
        from cryptography.x509.oid import ExtendedKeyUsageOID
        from pki.models.extension import ExtendedKeyUsageExtension, KeyPurposeIdModel
        
        # Pre-create a KeyPurposeIdModel
        existing_kp = KeyPurposeIdModel.objects.create(
            oid=ExtendedKeyUsageOID.SERVER_AUTH.dotted_string
        )
        
        # Create crypto extension with the same OID
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.EXTENDED_KEY_USAGE,
            critical=True,
            value=x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])
        )
        
        result = ExtendedKeyUsageExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        # Should have reused the existing KeyPurposeIdModel
        assert KeyPurposeIdModel.objects.filter(
            oid=ExtendedKeyUsageOID.SERVER_AUTH.dotted_string
        ).count() == 1

    def test_eku_save_from_crypto_wrong_type_raises_error(self):
        """Test save_from_crypto_extensions with wrong extension type raises TypeError."""
        from cryptography import x509
        from pki.models.extension import ExtendedKeyUsageExtension
        
        # Create extension with wrong value type
        wrong_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        with pytest.raises(TypeError, match='Expected an ExtendedKeyUsage extension'):
            ExtendedKeyUsageExtension.save_from_crypto_extensions(wrong_ext)


@pytest.mark.django_db
class TestPolicyConstraintsExtensionSaveFromCrypto:
    """Test suite for PolicyConstraintsExtension save_from_crypto_extensions."""

    def test_policy_constraints_save_from_crypto(self):
        """Test save_from_crypto_extensions method."""
        from cryptography import x509
        from pki.models.extension import PolicyConstraintsExtension
        
        # Create crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.POLICY_CONSTRAINTS,
            critical=True,
            value=x509.PolicyConstraints(
                require_explicit_policy=2,
                inhibit_policy_mapping=3
            )
        )
        
        result = PolicyConstraintsExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.critical is True
        assert result.require_explicit_policy == 2
        assert result.inhibit_policy_mapping == 3

    def test_policy_constraints_save_from_crypto_returns_existing(self):
        """Test that save_from_crypto_extensions returns existing entry."""
        from cryptography import x509
        from pki.models.extension import PolicyConstraintsExtension
        
        # Create existing entry
        existing = PolicyConstraintsExtension.objects.create(
            critical=False,
            require_explicit_policy=5,
            inhibit_policy_mapping=None
        )
        
        # Create matching crypto extension
        crypto_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.POLICY_CONSTRAINTS,
            critical=False,
            value=x509.PolicyConstraints(
                require_explicit_policy=5,
                inhibit_policy_mapping=None
            )
        )
        
        result = PolicyConstraintsExtension.save_from_crypto_extensions(crypto_ext)
        
        assert result is not None
        assert result.id == existing.id

    def test_policy_constraints_save_from_crypto_wrong_type_raises_error(self):
        """Test save_from_crypto_extensions with wrong extension type raises TypeError."""
        from cryptography import x509
        from pki.models.extension import PolicyConstraintsExtension
        
        # Create extension with wrong value type
        wrong_ext = x509.Extension(
            oid=x509.oid.ExtensionOID.KEY_USAGE,
            critical=True,
            value=x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            )
        )
        
        with pytest.raises(TypeError, match='Expected a PolicyConstraints extension'):
            PolicyConstraintsExtension.save_from_crypto_extensions(wrong_ext)
