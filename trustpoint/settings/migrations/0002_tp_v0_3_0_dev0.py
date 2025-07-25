# Generated by Django 5.1.9 on 2025-07-17 13:25

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('settings', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='backupoptions',
            options={'verbose_name': 'Backup Option'},
        ),
        migrations.AddField(
            model_name='backupoptions',
            name='sftp_storage',
            field=models.BooleanField(default=False, verbose_name='Use SFTP storage'),
        ),
        migrations.AlterField(
            model_name='backupoptions',
            name='auth_method',
            field=models.CharField(choices=[('password', 'Password'), ('ssh_key', 'SSH Key')], default='password', max_length=10, verbose_name='Authentication Method'),
        ),
        migrations.AlterField(
            model_name='backupoptions',
            name='host',
            field=models.CharField(blank=True, max_length=255, verbose_name='Host'),
        ),
        migrations.AlterField(
            model_name='backupoptions',
            name='port',
            field=models.PositiveIntegerField(blank=True, default=2222, verbose_name='Port'),
        ),
        migrations.AlterField(
            model_name='backupoptions',
            name='user',
            field=models.CharField(blank=True, max_length=128, verbose_name='Username'),
        ),
    ]
