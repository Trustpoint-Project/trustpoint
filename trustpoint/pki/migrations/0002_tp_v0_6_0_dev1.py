import django.db.models.deletion
import trustpoint.logger
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pki', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name='domainmodel',
            name='domain_credential_profile',
            field=models.ForeignKey(blank=True, help_text='Certificate profile used for issuing domain credentials. Defaults to "domain_credential".', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='domains_as_credential_profile', to='pki.certificateprofilemodel', verbose_name='Domain Credential Profile'),
        ),
        migrations.CreateModel(
            name='CaRolloverModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('state', models.CharField(choices=[('planned', 'Planned'), ('awaiting_new_ca', 'Awaiting New CA'), ('in_progress', 'In Progress'), ('completed', 'Completed'), ('cancelled', 'Cancelled')], default='planned', max_length=20, verbose_name='State')),
                ('strategy_type', models.CharField(choices=[('import_ca', 'Import new Issuing CA from file'), ('generate_keypair', 'Generate keypair and request certificate'), ('remote_ca', 'Configure a remote Issuing CA')], help_text='How the new Issuing CA is provisioned.', max_length=20, verbose_name='Strategy')),
                ('planned_at', models.DateTimeField(auto_now_add=True, verbose_name='Planned At')),
                ('started_at', models.DateTimeField(blank=True, null=True, verbose_name='Started At')),
                ('completed_at', models.DateTimeField(blank=True, null=True, verbose_name='Completed At')),
                ('overlap_end', models.DateTimeField(blank=True, help_text='When the old CA should stop being served in CA cert chains.', null=True, verbose_name='Overlap End')),
                ('notes', models.TextField(blank=True, default='', verbose_name='Notes')),
                ('initiated_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL, verbose_name='Initiated By')),
                ('new_issuing_ca', models.ForeignKey(blank=True, help_text='The replacement Issuing CA. Null until the new CA is ready.', null=True, on_delete=django.db.models.deletion.PROTECT, related_name='rollovers_as_new', to='pki.camodel', verbose_name='New Issuing CA')),
                ('old_issuing_ca', models.ForeignKey(help_text='The Issuing CA being replaced.', on_delete=django.db.models.deletion.PROTECT, related_name='rollovers_as_old', to='pki.camodel', verbose_name='Old Issuing CA')),
            ],
            options={
                'verbose_name': 'CA Rollover',
                'verbose_name_plural': 'CA Rollovers',
                'ordering': ['-planned_at'],
                'constraints': [models.UniqueConstraint(condition=models.Q(('state__in', ['planned', 'awaiting_new_ca', 'in_progress'])), fields=('old_issuing_ca',), name='unique_active_rollover_per_old_ca')],
            },
            bases=(trustpoint.logger.LoggerMixin, models.Model),
        ),
    ]
