import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
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
            ],
        ),
    ]
