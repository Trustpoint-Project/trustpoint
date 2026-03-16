import django.db.models.deletion
import django.utils.timezone
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Workflow2WorkerHeartbeat',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('worker_id', models.CharField(max_length=128, unique=True)),
                ('last_seen', models.DateTimeField(default=django.utils.timezone.now)),
            ],
        ),
        migrations.CreateModel(
            name='Workflow2Definition',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=200)),
                ('enabled', models.BooleanField(default=True)),
                ('trigger_on', models.CharField(db_index=True, default='', max_length=100)),
                ('yaml_text', models.TextField()),
                ('ir_json', models.JSONField()),
                ('ir_hash', models.CharField(max_length=64)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'indexes': [models.Index(fields=['enabled'], name='workflows2__enabled_2128e4_idx'), models.Index(fields=['trigger_on'], name='workflows2__trigger_c2c878_idx'), models.Index(fields=['ir_hash'], name='workflows2__ir_hash_55d9ec_idx')],
            },
        ),
        migrations.CreateModel(
            name='Workflow2Run',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('trigger_on', models.CharField(db_index=True, max_length=100)),
                ('event_json', models.JSONField()),
                ('source_json', models.JSONField(default=dict)),
                ('idempotency_key', models.CharField(blank=True, db_index=True, max_length=128, null=True)),
                ('status', models.CharField(choices=[('queued', 'Queued'), ('running', 'Running'), ('awaiting', 'Awaiting'), ('paused', 'Paused'), ('succeeded', 'Succeeded'), ('stopped', 'Stopped'), ('rejected', 'Rejected'), ('failed', 'Failed'), ('cancelled', 'Cancelled'), ('no_match', 'No match')], default='queued', max_length=16)),
                ('finalized', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'indexes': [models.Index(fields=['trigger_on', 'created_at'], name='workflows2__trigger_aff43b_idx'), models.Index(fields=['status'], name='workflows2__status_0963f7_idx'), models.Index(fields=['finalized'], name='workflows2__finaliz_bd923f_idx'), models.Index(fields=['idempotency_key'], name='workflows2__idempot_b0391d_idx')],
            },
        ),
        migrations.CreateModel(
            name='Workflow2Instance',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('event_json', models.JSONField()),
                ('vars_json', models.JSONField(default=dict)),
                ('status', models.CharField(choices=[('queued', 'Queued'), ('running', 'Running'), ('awaiting', 'Awaiting'), ('paused', 'Paused'), ('succeeded', 'Succeeded'), ('stopped', 'Stopped'), ('rejected', 'Rejected'), ('failed', 'Failed'), ('cancelled', 'Cancelled')], default='queued', max_length=16)),
                ('current_step', models.CharField(blank=True, max_length=200, null=True)),
                ('run_count', models.PositiveIntegerField(default=0)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('definition', models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name='instances', to='workflows2.workflow2definition')),
                ('run', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='instances', to='workflows2.workflow2run')),
            ],
        ),
        migrations.CreateModel(
            name='Workflow2StepRun',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('run_index', models.PositiveIntegerField()),
                ('step_id', models.CharField(max_length=200)),
                ('step_type', models.CharField(max_length=50)),
                ('status', models.CharField(max_length=16)),
                ('outcome', models.CharField(blank=True, max_length=100, null=True)),
                ('next_step', models.CharField(blank=True, max_length=200, null=True)),
                ('vars_delta', models.JSONField(blank=True, null=True)),
                ('output', models.JSONField(blank=True, null=True)),
                ('error', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='runs', to='workflows2.workflow2instance')),
            ],
        ),
        migrations.CreateModel(
            name='Workflow2DefinitionUiState',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ir_hash', models.CharField(db_index=True, max_length=64)),
                ('version', models.PositiveIntegerField(default=1)),
                ('state_json', models.JSONField(default=dict)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('definition', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ui_states', to='workflows2.workflow2definition')),
            ],
            options={
                'indexes': [models.Index(fields=['definition', 'ir_hash'], name='workflows2__definit_c69491_idx'), models.Index(fields=['ir_hash'], name='workflows2__ir_hash_3fa6b6_idx')],
                'unique_together': {('definition', 'ir_hash')},
            },
        ),
        migrations.CreateModel(
            name='Workflow2Approval',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('step_id', models.CharField(max_length=200)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('approved', 'Approved'), ('rejected', 'Rejected'), ('expired', 'Expired')], default='pending', max_length=16)),
                ('expires_at', models.DateTimeField(blank=True, null=True)),
                ('decided_at', models.DateTimeField(blank=True, null=True)),
                ('decided_by', models.CharField(blank=True, max_length=128, null=True)),
                ('comment', models.TextField(blank=True, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='approvals', to='workflows2.workflow2instance')),
            ],
            options={
                'indexes': [models.Index(fields=['status', 'expires_at'], name='workflows2__status_9c0f0f_idx'), models.Index(fields=['instance', 'step_id'], name='workflows2__instanc_351254_idx')],
            },
        ),
        migrations.CreateModel(
            name='Workflow2Job',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('kind', models.CharField(choices=[('run', 'Run'), ('resume', 'Resume')], max_length=16)),
                ('status', models.CharField(choices=[('queued', 'Queued'), ('running', 'Running'), ('done', 'Done'), ('failed', 'Failed'), ('cancelled', 'Cancelled')], default='queued', max_length=16)),
                ('run_after', models.DateTimeField(default=django.utils.timezone.now)),
                ('attempts', models.PositiveIntegerField(default=0)),
                ('max_attempts', models.PositiveIntegerField(default=0)),
                ('last_error', models.TextField(blank=True, null=True)),
                ('locked_until', models.DateTimeField(blank=True, null=True)),
                ('locked_by', models.CharField(blank=True, max_length=128, null=True)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='jobs', to='workflows2.workflow2instance')),
            ],
            options={
                'indexes': [models.Index(fields=['status', 'run_after'], name='workflows2__status_5f0b2f_idx'), models.Index(fields=['locked_until'], name='workflows2__locked__1f04a6_idx'), models.Index(fields=['instance', 'status'], name='workflows2__instanc_95feba_idx')],
            },
        ),
        migrations.AddIndex(
            model_name='workflow2instance',
            index=models.Index(fields=['status'], name='workflows2__status_2afdb8_idx'),
        ),
        migrations.AddIndex(
            model_name='workflow2instance',
            index=models.Index(fields=['created_at'], name='workflows2__created_b79f7a_idx'),
        ),
        migrations.AddIndex(
            model_name='workflow2instance',
            index=models.Index(fields=['run', 'status'], name='workflows2__run_id_2f7c53_idx'),
        ),
        migrations.AddIndex(
            model_name='workflow2steprun',
            index=models.Index(fields=['instance', 'run_index'], name='workflows2__instanc_c347b2_idx'),
        ),
        migrations.AddIndex(
            model_name='workflow2steprun',
            index=models.Index(fields=['step_id'], name='workflows2__step_id_4cbee1_idx'),
        ),
    ]
