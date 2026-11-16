# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Unify solved status records and move name escaping to HTML rendering."""

from html import escape, unescape

from django.db import migrations


def update_message_data(apps, schema_editor, transform):
    notifications = apps.get_model('management', 'NotificationModel').objects.using(schema_editor.connection.alias)
    for notification in notifications.filter(
        message_type__in=(
            'USER_CERT_EXPIRING',
            'USER_CERT_EXPIRED',
            'API_CRED_EXPIRING',
            'API_CRED_EXPIRED',
            'CRYPTO_BACKEND_UNAVAILABLE',
            'ACCOUNT_LOCKED',
            'WORKFLOW_FAILED',
            'WORKFLOW_APPROVAL_OVERDUE',
        )
    ).iterator():
        data = dict(notification.message_data)
        for key in ('username', 'identifier', 'workflow', 'backend'):
            if isinstance(data.get(key), str):
                data[key] = transform(data[key])
        if data != notification.message_data:
            notifications.filter(pk=notification.pk).update(message_data=data)


def normalize_notifications(apps, schema_editor):
    statuses = apps.get_model('management', 'NotificationStatus').objects.using(schema_editor.connection.alias)
    legacy = statuses.filter(status='SOLVED').first()
    if legacy is not None:
        solved, _ = statuses.get_or_create(status='SOLV')
        links = apps.get_model('management', 'NotificationModel').statuses.through.objects.using(
            schema_editor.connection.alias,
        )
        already_solved = links.filter(notificationstatus_id=solved.pk).values('notificationmodel_id')
        links.filter(notificationstatus_id=legacy.pk).exclude(
            notificationmodel_id__in=already_solved,
        ).update(notificationstatus_id=solved.pk)
        legacy.delete(using=schema_editor.connection.alias)
    update_message_data(apps, schema_editor, unescape)


def restore_escaped_data(apps, schema_editor):
    update_message_data(apps, schema_editor, escape)


class Migration(migrations.Migration):
    dependencies = [('management', '0011_operational_notifications')]

    operations = [migrations.RunPython(normalize_notifications, restore_escaped_data)]
