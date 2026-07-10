import django.db.models.deletion
import trustpoint.logger
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('crypto', '0001_tp_v0_6_0_dev1'),
        ('pki', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='CaRolloverModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('state', models.CharField(choices=[('planned', 'Planned'), ('awaiting_new_ca', 'Awaiting New CA'), ('preparation', 'Preparation'), ('transition', 'Transition'), ('completed', 'Completed'), ('cancelled', 'Cancelled')], default='planned', max_length=20, verbose_name='State')),
                ('strategy_type', models.CharField(choices=[('import_ca', 'Import new Issuing CA from file'), ('generate_keypair', 'Generate keypair and request certificate'), ('remote_ca', 'Configure a remote Issuing CA')], help_text='How the new Issuing CA is provisioned.', max_length=20, verbose_name='Strategy')),
                ('planned_at', models.DateTimeField(auto_now_add=True, verbose_name='Planned At')),
                ('started_at', models.DateTimeField(blank=True, null=True, verbose_name='Started At')),
                ('completed_at', models.DateTimeField(blank=True, null=True, verbose_name='Completed At')),
                ('transition_scheduled_at', models.DateTimeField(blank=True, help_text='When the rollover should automatically move from Preparation to Transition phase.', null=True, verbose_name='Scheduled Transition Time')),
                ('notes', models.TextField(blank=True, default='', verbose_name='Notes')),
            ],
            options={
                'verbose_name': 'CA Rollover',
                'verbose_name_plural': 'CA Rollovers',
                'ordering': ['-planned_at'],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
        migrations.AlterUniqueTogether(
            name='pkcs11key',
            unique_together=None,
        ),
        migrations.RemoveField(
            model_name='credentialmodel',
            name='pkcs11_private_key',
        ),
        migrations.AddField(
            model_name='certificateprofilemodel',
            name='credential_type',
            field=models.CharField(choices=[('application', 'Application Credential'), ('domain', 'Domain Credential')], default='application', max_length=32),
        ),
        migrations.AddField(
            model_name='credentialmodel',
            name='managed_private_key',
            field=models.ForeignKey(blank=True, help_text='Reference to the configured Trustpoint crypto backend managed key', null=True, on_delete=django.db.models.deletion.PROTECT, to='crypto.cryptomanagedkeymodel', verbose_name='Managed Private Key'),
        ),
        migrations.AddField(
            model_name='domainmodel',
            name='domain_credential_profile',
            field=models.ForeignKey(blank=True, help_text='Certificate profile used for issuing domain credentials. Defaults to "domain_credential".', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='domains_as_credential_profile', to='pki.certificateprofilemodel', verbose_name='Domain Credential Profile'),
        ),
        migrations.AlterField(
            model_name='camodel',
            name='ca_type',
            field=models.IntegerField(blank=True, choices=[(-1, 'Keyless CA'), (0, 'Auto-Generated Root'), (1, 'Auto-Generated'), (2, 'Local-Legacy Software'), (3, 'Local-Managed Backend'), (4, 'Remote-EST-RA'), (5, 'Remote-CMP-RA'), (6, 'Remote-Issuing-EST'), (7, 'Remote-Issuing-CMP')], help_text='Type of CA - KEYLESS for keyless CAs', null=True, verbose_name='CA Type'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['not_valid_after'], name='pki_cert_not_valid_after_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['not_valid_before'], name='pki_cert_not_valid_before_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['serial_number'], name='pki_cert_serial_num_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['subject_public_bytes'], name='pki_cert_subj_pub_bytes_idx'),
        ),
        migrations.AddIndex(
            model_name='certificatemodel',
            index=models.Index(fields=['issuer_public_bytes', 'issuer_id'], name='pki_cert_iss_pub_bytes_idx'),
        ),
        migrations.AddIndex(
            model_name='revokedcertificatemodel',
            index=models.Index(fields=['ca', 'revoked_at'], name='pki_revoked_ca_revoked_at_idx'),
        ),
    ]
