"""Database model utilities for Trustpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from django.db import models
from django.db.models import ProtectedError
from django.db.models.signals import post_delete, pre_delete

from trustpoint.views.base import LoggerMixin

if TYPE_CHECKING:
    from django.db.models.fields.related import RelatedField
    _Base = RelatedField
    _ModelBase = models.Model
else:
    _Base = object
    _ModelBase = object


class AutoDeleteRelatedMixin(_Base):
    """Utility for deleting the object referenced by a relation when the parent object is deleted.

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
        del sender, kwargs
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
            print('Checking references for ' + link.name)
            print(link.get_accessor_name())
            references_exist = getattr(related_object, link.get_accessor_name()).exists()
            if references_exist:
                print(f'References exist for {link.name}')
                return
            """print('Name: ' + link.name)
            for object in objects:
                print(object)"""

        print('No references found. Deleting related object ' + str(related_object))
        #if related_object.pk:
        related_object.delete()

class AutoDeleteRelatedForeignKey(AutoDeleteRelatedMixin, models.ForeignKey):
    """A ForeignKey that deletes the object referenced by the FK when the parent object is deleted.

    This is useful for cases when a parent object is deleted, related objects should be deleted as well.
    """

class SelfProtectMixin(LoggerMixin, _Base):
    """A mixin that protects the parent object from being deleted if another object is referenced.

    This makes the model instance only deleteable via e.g. on_delete=models.CASCADE.
    """
    def contribute_to_class(self, cls: type[models.Model], name: str, *args: Any) -> None:
        """Register the signal when the model class is fully prepared."""
        super().contribute_to_class(cls, name, *args)
        pre_delete.connect(self._check_reference, sender=cls)

    def _check_reference(self, sender: models.Model, instance: models.Model, **kwargs: Any) -> None:
        del sender, kwargs
        if not self.name:
            return
        related_object = getattr(instance, self.name, None)

        if not related_object:
            return

        exc_msg = f'Cannot delete {instance} because it still references {related_object}.'
        self.logger.error(exc_msg)
        raise ProtectedError(exc_msg, {instance})


class SelfProtectForeignKey(SelfProtectMixin, models.ForeignKey):
    """A ForeignKey that protects the parent object from being deleted if another object is referenced.

    This makes the model instance only deleteable via e.g. on_delete=models.CASCADE.
    """


class SelfProtectOneToOneField(SelfProtectMixin, models.OneToOneField):
    """A OneToOneField that protects the parent object from being deleted if another object is referenced.

    This makes the model instance only deleteable via e.g. on_delete=models.CASCADE.
    """


class IndividualDeleteQuerySet(models.QuerySet):
    """Overrides a model's queryset to use individual delete instead of bulk delete.

    This ensures the model instance delete() method is always called, even when deleting a queryset.
    """
    def delete(self) -> tuple[int, dict[str, int]]:
        """Delete each object individually."""
        count: int = 0
        for obj in self:
            obj.delete()
            count += 1
        # using _meta to return model name to keep API from superclass
        if count == 0:
            return 0, {}
        return count, {obj._meta.label: count}  # noqa: SLF001

class IndividualDeleteManager(models.Manager):
    """Overrides a model's manager to use individual delete instead of bulk delete.

    This ensures the model instance delete() method is always
    called, even when deleting a queryset.
    """
    def get_queryset(self) -> IndividualDeleteQuerySet:
        """Return the queryset with individual delete."""
        return IndividualDeleteQuerySet(self.model, using=self._db)

class IndividualDeleteMixin(_ModelBase):
    """Mixin to override a model's queryset to use individual delete instead of bulk delete.

    This ensures the model instance delete() method is always called, even when deleting a queryset.
    """
    objects = IndividualDeleteManager()

    class Meta:
        """Meta options."""
        abstract = True
