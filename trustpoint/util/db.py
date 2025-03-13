"""Database model utilities for Trustpoint."""

from __future__ import annotations

from typing import Any

from django.db import models
from django.db.models.signals import post_delete


class AutoDeleteRelatedForeignKey(models.ForeignKey):
    """A ForeignKey that deletes the object referenced by the FK when the parent object is deleted.

    This is useful for cases when a parent object is deleted, related objects should be deleted as well.
    """

    def contribute_to_class(self, cls: type[models.Model], name: str, *args: Any) -> None:
        """Register the signal when the model class is fully prepared."""
        super().contribute_to_class(cls, name, *args)
        post_delete.connect(self._delete_referenced_model, sender=cls)

    def _delete_referenced_model(self, sender: models.Model, instance: models.Model, **kwargs: Any) -> None:
        """Delete the referenced model.

        Automagically checks if the referenced model is still referenced by other objects
        (even in other models) and only deletes it if it is not.
        """
        del kwargs
        del sender
        if not self.name:
            return
        related_object = getattr(instance, self.name, None)

        if not related_object:
            return
        # get ReferencedManager of the related object and check if there are still references somewhere else
        # works for ForeignKey as well as ManyToManyField
        # TODO: check OneToOneField
        related_model_cls = self.related_model
        links = [
            f for f in related_model_cls._meta.get_fields()
            if (f.one_to_many or f.one_to_one)
            and f.auto_created and not f.concrete
        ]

        for link in links:
            references_exist = getattr(related_object, link.name).exists()
            if references_exist:
                print(f'References exist for {link.name}')
                return
            """print('Name: ' + link.name)
            for object in objects:
                print(object)"""

        print('No references found. Deleting related object ' + str(related_object))
        #if related_object.pk:
        related_object.delete()
