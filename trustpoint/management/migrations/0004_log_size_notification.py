from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('management', '0003_tp_v1_0_dev0'),
    ]

    operations = [
        migrations.AlterField(
            model_name='notificationmodel',
            name='message_type',
            field=models.CharField(choices=[('C', 'custom'), ('TEST_CA', 'Issuing Ca Test'), ('TEST_DOMAIN', 'Domain Test'), ('TEST_CERT', 'Cert Test'), ('TEST_DEVICE', 'Device Test'), ('POP_TEST_DATA', 'Welcome Populate Test Data'), ('TP_DOCS', 'Trustpoint Documentation'), ('TP_INFO', 'Trustpoint Project Info'), ('WELCOME', 'Welcome Message'), ('SYS_NOT_HEALTHY', 'System Not Healthy'), ('LOG_SIZE_EXCEEDED', 'Log Size Exceeded'), ('VULNERABILITY', 'Vulnerability'), ('CERT_EXPIRING', 'Cert Expiring'), ('CERT_EXPIRED', 'Cert Expired'), ('CA_EXPIRING', 'Issuing Ca Expiring'), ('CA_EXPIRED', 'Issuing Ca Expired'), ('DOMAIN_NO_CA', 'Domain No Issuing Ca'), ('DEV_NOT_ONBRD', 'Device Not Onboarded'), ('DEV_ONBRD_FAIL', 'Device Onboarding Failed'), ('DEV_CERT_REV', 'Device Cert Revoked'), ('WEAK_SIG_ALGO', 'Weak Signature Algorithm'), ('INSUFF_KEY_LEN', 'Insufficient Key Length'), ('WEAK_ECC_CURVE', 'Weak Ecc Curve'), ('CRL_EXPIRING', 'Crl Expiring'), ('CRL_EXPIRED', 'Crl Expired'), ('GDS_PUSH_FAIL', 'Gds Push Failed'), ('SIGN_KEY_EXP', 'Signer Key Expiring'), ('SIGN_KEY_EXPRD', 'Signer Key Expired'), ('TLS_CERT_EXP', 'Tls Cert Expiring'), ('TLS_CERT_EXPRD', 'Tls Cert Expired')], default='C', max_length=32),
        ),
    ]
