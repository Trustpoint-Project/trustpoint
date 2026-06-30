"""Test suite for IPv4AddressForm."""
from django.test import TestCase

from management.forms import IPv4AddressForm


class IPv4AddressFormTest(TestCase):
    """Test suite for IPv4AddressForm."""

    def test_form_initialization_with_san_ips(self):
        """Test form initializes with SAN IPs."""
        san_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        form = IPv4AddressForm(san_ips=san_ips)

        choices = form.fields['ipv4_address'].choices
        self.assertEqual(len(choices), 3)
        self.assertIn(('192.168.1.1', '192.168.1.1'), choices)

    def test_form_initialization_with_saved_ipv4_not_in_san(self):
        """Test form adds saved IPv4 address if not in SAN list."""
        san_ips = ['192.168.1.1', '10.0.0.1']
        saved_ip = '172.16.0.1'

        form = IPv4AddressForm(
            san_ips=san_ips,
            initial={'ipv4_address': saved_ip}
        )

        choices = form.fields['ipv4_address'].choices
        # Should have 3 choices: saved IP + 2 SAN IPs
        self.assertEqual(len(choices), 3)
        # Saved IP should be first
        self.assertEqual(choices[0], (saved_ip, saved_ip))

    def test_form_initialization_with_saved_ipv4_in_san(self):
        """Test form doesn't duplicate IP if already in SAN list."""
        san_ips = ['192.168.1.1', '10.0.0.1', '172.16.0.1']
        saved_ip = '192.168.1.1'

        form = IPv4AddressForm(
            san_ips=san_ips,
            initial={'ipv4_address': saved_ip}
        )

        choices = form.fields['ipv4_address'].choices
        # Should still have 3 choices, no duplication
        self.assertEqual(len(choices), 3)

    def test_form_initialization_without_san_ips(self):
        """Test form initializes with empty SAN IPs list."""
        form = IPv4AddressForm()
        choices = form.fields['ipv4_address'].choices
        self.assertEqual(len(choices), 0)

    def test_form_field_label(self):
        """Test that ipv4_address field has correct label."""
        form = IPv4AddressForm()
        self.assertEqual(form.fields['ipv4_address'].label, 'Update IPv4 Address')
