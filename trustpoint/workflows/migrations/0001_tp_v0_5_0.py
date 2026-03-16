import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('devices', '0001_tp_v0_5_0'),
        ('pki', '0001_tp_v0_5_0'),
    ]

    operations = [
        migrations.CreateModel(
            name='WorkflowDefinition',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=100, unique=True)),
                ('version', models.PositiveIntegerField(default=1)),
                ('published', models.BooleanField(default=False)),
                ('definition', models.JSONField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'workflow_definitions',
                'ordering': ('-created_at',),
            },
        ),
        migrations.CreateModel(
            name='DeviceRequest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action', models.CharField(max_length=32)),
                ('payload', models.JSONField(blank=True, default=dict)),
                ('aggregated_state', models.CharField(choices=[('Running', 'Running'), ('AwaitingApproval', 'AwaitingApproval'), ('Approved', 'Approved'), ('Passed', 'Passed'), ('Finalized', 'Finalized'), ('Rejected', 'Rejected'), ('Failed', 'Failed'), ('Aborted', 'Aborted'), ('Stopped', 'Stopped')], default='Running', max_length=32)),
                ('finalized', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('ca', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='device_requests', to='pki.camodel')),
                ('device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='device_requests', to='devices.devicemodel')),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='device_requests', to='pki.domainmodel')),
            ],
            options={
                'ordering': ('-created_at',),
            },
        ),
        migrations.CreateModel(
            name='EnrollmentRequest',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('protocol', models.CharField(max_length=50)),
                ('operation', models.CharField(max_length=50)),
                ('fingerprint', models.CharField(max_length=128)),
                ('template', models.CharField(blank=True, default='', max_length=100)),
                ('aggregated_state', models.CharField(choices=[('Running', 'Running'), ('AwaitingApproval', 'AwaitingApproval'), ('Approved', 'Approved'), ('Passed', 'Passed'), ('Finalized', 'Finalized'), ('Rejected', 'Rejected'), ('Failed', 'Failed'), ('Aborted', 'Aborted'), ('Stopped', 'Stopped')], default='AwaitingApproval', max_length=32)),
                ('finalized', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('ca', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='enrollment_requests', to='pki.camodel')),
                ('device', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='enrollment_requests', to='devices.devicemodel')),
                ('domain', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='enrollment_requests', to='pki.domainmodel')),
            ],
            options={
                'db_table': 'enrollment_requests',
            },
        ),
        migrations.CreateModel(
            name='WorkflowInstance',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('current_step', models.CharField(help_text='Current step id (e.g. "step-1").', max_length=100)),
                ('state', models.CharField(choices=[('Running', 'Running'), ('AwaitingApproval', 'AwaitingApproval'), ('Approved', 'Approved'), ('Passed', 'Passed'), ('Finalized', 'Finalized'), ('Rejected', 'Rejected'), ('Failed', 'Failed'), ('Aborted', 'Aborted'), ('Stopped', 'Stopped')], default='Running', max_length=32)),
                ('payload', models.JSONField(help_text='Immutable instance inputs (ids, fingerprint, CSR, etc.).')),
                ('step_contexts', models.JSONField(default=dict, help_text="Mutable runtime storage (per-step contexts + reserved engine buckets like '$vars').")),
                ('finalized', models.BooleanField(default=False, help_text='Once true, this instance will never be advanced again.')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('definition', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='instances', to='workflows.workflowdefinition')),
                ('device_request', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='instances', to='workflows.devicerequest')),
                ('enrollment_request', models.ForeignKey(blank=True, help_text='Parent request for enrollment fan-out orchestration.', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='instances', to='workflows.enrollmentrequest')),
            ],
            options={
                'db_table': 'workflow_instances',
            },
        ),
        migrations.CreateModel(
            name='WorkflowScope',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('ca', models.ForeignKey(blank=True, db_column='ca_id', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='workflow_scopes', to='pki.camodel')),
                ('device', models.ForeignKey(blank=True, db_column='device_id', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='workflow_scopes', to='devices.devicemodel')),
                ('domain', models.ForeignKey(blank=True, db_column='domain_id', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='workflow_scopes', to='pki.domainmodel')),
                ('workflow', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scopes', to='workflows.workflowdefinition')),
            ],
            options={
                'db_table': 'workflow_scopes',
            },
        ),
        migrations.CreateModel(
            name='WorkflowStepRun',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('run_index', models.PositiveIntegerField(help_text='Monotonic per-instance sequence number (1..n).')),
                ('step_id', models.CharField(help_text='Raw step id (e.g. "step-1").', max_length=100)),
                ('step_type', models.CharField(help_text='Step type (e.g. "Webhook", "Logic").', max_length=50)),
                ('status', models.CharField(choices=[('Running', 'Running'), ('AwaitingApproval', 'AwaitingApproval'), ('Approved', 'Approved'), ('Passed', 'Passed'), ('Finalized', 'Finalized'), ('Rejected', 'Rejected'), ('Failed', 'Failed'), ('Aborted', 'Aborted'), ('Stopped', 'Stopped')], help_text='Executor returned State.', max_length=32)),
                ('context', models.JSONField(blank=True, null=True)),
                ('vars_delta', models.JSONField(blank=True, null=True)),
                ('next_step', models.CharField(blank=True, max_length=100, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('instance', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='step_runs', to='workflows.workflowinstance')),
            ],
            options={
                'db_table': 'workflow_step_runs',
                'ordering': ('instance_id', 'run_index'),
            },
        ),
        migrations.AddIndex(
            model_name='enrollmentrequest',
            index=models.Index(fields=['protocol', 'operation', 'ca_id', 'domain_id', 'device_id', 'fingerprint', 'template'], name='enrollment__protoco_ab5ce2_idx'),
        ),
        migrations.AddIndex(
            model_name='enrollmentrequest',
            index=models.Index(fields=['aggregated_state'], name='enrollment__aggrega_7c0743_idx'),
        ),
        migrations.AddIndex(
            model_name='enrollmentrequest',
            index=models.Index(fields=['finalized'], name='enrollment__finaliz_a5e5e1_idx'),
        ),
        migrations.AddIndex(
            model_name='workflowinstance',
            index=models.Index(fields=['state'], name='workflow_in_state_71d4ab_idx'),
        ),
        migrations.AddIndex(
            model_name='workflowinstance',
            index=models.Index(fields=['finalized'], name='workflow_in_finaliz_c967eb_idx'),
        ),
        migrations.AddConstraint(
            model_name='workflowscope',
            constraint=models.UniqueConstraint(fields=('workflow', 'ca', 'domain', 'device'), name='uq_workflow_scope_workflow_ca_domain_device'),
        ),
        migrations.AddIndex(
            model_name='workflowsteprun',
            index=models.Index(fields=['instance', 'run_index'], name='workflow_st_instanc_63cd94_idx'),
        ),
        migrations.AddIndex(
            model_name='workflowsteprun',
            index=models.Index(fields=['instance', 'step_id'], name='workflow_st_instanc_a008bb_idx'),
        ),
        migrations.AddIndex(
            model_name='workflowsteprun',
            index=models.Index(fields=['status'], name='workflow_st_status_444ecd_idx'),
        ),
        migrations.AddIndex(
            model_name='workflowsteprun',
            index=models.Index(fields=['created_at'], name='workflow_st_created_fe8ca4_idx'),
        ),
        migrations.AddConstraint(
            model_name='workflowsteprun',
            constraint=models.UniqueConstraint(fields=('instance', 'run_index'), name='uq_workflow_step_run_instance_run_index'),
        ),
    ]
