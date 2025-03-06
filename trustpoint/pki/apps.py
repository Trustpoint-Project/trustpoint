from django.apps import AppConfig


class PkiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'pki'

    def ready(self) -> None:
        from pki.signals.issuing_ca import (
            delete_related_credential_certificate_chain_order_records,
            delete_related_credential_record,
        )
