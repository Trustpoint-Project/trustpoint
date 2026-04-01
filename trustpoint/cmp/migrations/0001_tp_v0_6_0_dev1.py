import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('devices', '0002_tp_v0_5_0'),
        ('pki', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='CmpTransactionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(db_index=True, help_text='Hex-encoded CMP transactionID from the PKIHeader.', max_length=64, unique=True, verbose_name='Transaction ID')),
                ('operation', models.CharField(help_text='CMP management operation, for example initialization or certification.', max_length=32, verbose_name='CMP Operation')),
                ('request_body_type', models.CharField(help_text='Original CMP request body type, for example ir or cr.', max_length=16, verbose_name='Request Body Type')),
                ('domain_name', models.CharField(blank=True, default='', help_text='Original CMP domain path segment, even when no Domain FK could be resolved.', max_length=255, verbose_name='Domain Name')),
                ('cert_profile', models.CharField(blank=True, default='', max_length=255, verbose_name='Certificate Profile')),
                ('cert_req_id', models.PositiveIntegerField(default=0, help_text='CertResponse identifier referenced by pollReq / pollRep.', verbose_name='certReqId')),
                ('request_der', models.BinaryField(help_text='Original CMP enrollment PKIMessage in DER form.', verbose_name='Original Request (DER)')),
                ('implicit_confirm', models.BooleanField(default=False, verbose_name='Implicit Confirm Requested')),
                ('status', models.CharField(choices=[('processing', 'Processing'), ('waiting', 'Waiting'), ('issued', 'Issued'), ('rejected', 'Rejected'), ('failed', 'Failed'), ('cancelled', 'Cancelled')], db_index=True, default='processing', max_length=16, verbose_name='Status')),
                ('detail', models.TextField(blank=True, default='', verbose_name='Detail')),
                ('check_after_seconds', models.PositiveIntegerField(default=5, verbose_name='Check After (Seconds)')),
                ('backend', models.CharField(blank=True, choices=[('', 'None'), ('workflow2', 'Workflow 2')], default='', max_length=32, verbose_name='Backend')),
                ('backend_reference', models.CharField(blank=True, default='', max_length=128, verbose_name='Backend Reference')),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now, verbose_name='Created At')),
                ('updated_at', models.DateTimeField(auto_now=True, verbose_name='Updated At')),
                ('finalized_at', models.DateTimeField(blank=True, null=True, verbose_name='Finalized At')),
                ('device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='cmp_transactions', to='devices.devicemodel', verbose_name='Device')),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, related_name='cmp_transactions', to='pki.domainmodel', verbose_name='Domain')),
                ('final_certificate', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cmp_transaction_records', to='pki.certificatemodel', verbose_name='Final Certificate')),
                ('issuer_credential', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cmp_transaction_issuer_records', to='pki.credentialmodel', verbose_name='Issuer Credential')),
            ],
            options={
                'indexes': [models.Index(fields=['status'], name='cmp_cmptran_status_bca250_idx'), models.Index(fields=['backend', 'backend_reference'], name='cmp_cmptran_backend_ba899c_idx'), models.Index(fields=['device', 'status'], name='cmp_cmptran_device__000381_idx'), models.Index(fields=['domain', 'status'], name='cmp_cmptran_domain__3132e9_idx')],
            },
        ),
    ]
