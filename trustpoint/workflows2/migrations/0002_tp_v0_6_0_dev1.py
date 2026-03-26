from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('workflows2', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.AlterField(
            model_name='workflow2approval',
            name='comment',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AlterField(
            model_name='workflow2approval',
            name='decided_by',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AlterField(
            model_name='workflow2instance',
            name='current_step',
            field=models.CharField(blank=True, default='', max_length=200),
        ),
        migrations.AlterField(
            model_name='workflow2job',
            name='last_error',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AlterField(
            model_name='workflow2job',
            name='locked_by',
            field=models.CharField(blank=True, default='', max_length=128),
        ),
        migrations.AlterField(
            model_name='workflow2run',
            name='idempotency_key',
            field=models.CharField(blank=True, db_index=True, default='', max_length=128),
        ),
        migrations.AlterField(
            model_name='workflow2steprun',
            name='error',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AlterField(
            model_name='workflow2steprun',
            name='next_step',
            field=models.CharField(blank=True, default='', max_length=200),
        ),
        migrations.AlterField(
            model_name='workflow2steprun',
            name='outcome',
            field=models.CharField(blank=True, default='', max_length=100),
        ),
        migrations.AddConstraint(
            model_name='workflow2job',
            constraint=models.UniqueConstraint(condition=models.Q(('status__in', ('queued', 'running'))), fields=('instance',), name='wf2_job_one_active_per_instance'),
        ),
        migrations.AddConstraint(
            model_name='workflow2run',
            constraint=models.UniqueConstraint(condition=models.Q(('idempotency_key', ''), _negated=True), fields=('trigger_on', 'idempotency_key'), name='wf2_run_on_idem_uniq'),
        ),
    ]
