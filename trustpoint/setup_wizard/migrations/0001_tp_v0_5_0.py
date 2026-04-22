from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='SetupWizardCompletedModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('setup_completed_at', models.DateTimeField(blank=True, help_text='Timestamp when initial setup was completed. Write-once once set.', null=True)),
            ],
        ),
        migrations.CreateModel(
            name='SetupWizardConfigurationModel',
            fields=[
                ('singleton_id', models.PositiveSmallIntegerField(default=1, editable=False, help_text='Singleton primary key. Always 1.', primary_key=True, serialize=False)),
                ('inject_demo_data', models.BooleanField(default=False, help_text='Inject demo data.')),
            ],
        ),
    ]
