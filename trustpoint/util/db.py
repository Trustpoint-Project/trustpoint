"""Database model utilities for Trustpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, TypeVar, final

from django.db import models, transaction
from django.db.models import ProtectedError
from django.db.models.signals import post_delete

from trustpoint.views.base import LoggerMixin

if TYPE_CHECKING:
    from django.db.models.fields.related import RelatedField

    _Base = RelatedField
    _ModelBase = models.Model
else:
    _Base = object
    _ModelBase = object

T = TypeVar('T', bound=models.Model)


class AutoDeleteRelatedMixin(LoggerMixin, _Base):
    """Utility for deleting the object referenced by a relation when the parent object is deleted.

    This is useful for cases when a parent object is deleted, related objects should be deleted as well.
    """
    do_reference_check: bool

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initializes the AutoDeleteRelatedMixin object.

        Args:
            *args: Positional arguments passed to super().__init__().
            **kwargs: Keyword arguments, for reference check, and passed to super().__init__().

        With kwarg "do_reference_check=True" (default):
            Automagically checks if the referenced model is still referenced by other objects
            (even in other models) and only deletes it if it is not.

        With kwarg "do_reference_check=False":
            Always deletes the referenced model. Faster as it skips the reference check.
            If there are other references using on_delete=models.PROTECT,
            the object is kept in the database if still referenced.
            WARNING: This requires ALL references to the referenced model to use on_delete=models.PROTECT
            as they may not only delete the referenced model despite not being orphaned,
            but could also cascade delete those other referencing models inadvertently.
        """
        self.do_reference_check = kwargs.pop('do_reference_check', True)
        super().__init__(*args, **kwargs)

    def contribute_to_class(self, cls: type[models.Model], name: str, *args: Any) -> None:
        """Register the signal when the model class is fully prepared."""
        super().contribute_to_class(cls, name, *args)
        post_delete.connect(self._delete_referenced_model, sender=cls)

    def _has_references(self, related_object: _ModelBase) -> bool:
        """Get ReferencedManager of the related object and check if there are still references somewhere else.

        Works for ForeignKey as well as ManyToManyField
        """
        related_model_cls = self.related_model
        links = [
            f
            for f in related_model_cls._meta.get_fields()   # noqa: SLF001
            if (f.one_to_many or f.one_to_one) and f.auto_created and not f.concrete
        ]

        for link in links:
            log_msg = 'Checking references for ' + link.name
            self.logger.debug(log_msg)
            references_exist = getattr(related_object, link.get_accessor_name()).exists()
            if references_exist:
                log_msg = f'References exist for {link.name}'
                self.logger.debug(log_msg)
                return True

        log_msg = f'No refs found. Deleting related obj {related_object}'
        self.logger.debug(log_msg)
        return False

    def _delete_referenced_model(self, sender: models.Model, instance: models.Model, **kwargs: Any) -> None:
        """Signal receiver that deletes the referenced model."""
        del sender, kwargs
        if not self.name:
            return
        related_object = getattr(instance, self.name, None)

        if not related_object:
            return

        if self.do_reference_check and self._has_references(related_object):
            return

        if related_object.pk:
            try:
                related_object.delete()
            except ProtectedError:
                # is still referenced by other objects with on_delete=models.PROTECT and kept in the database
                return

class AutoDeleteRelatedForeignKey(AutoDeleteRelatedMixin, models.ForeignKey):
    """A ForeignKey that deletes the object referenced by the FK when the parent object is deleted.

    This is useful for cases when a parent object is deleted, related objects should be deleted as well.
    """

# TODO(all): defining a type var with a str literal as bound causes mypy to crash (cmp. https://github.com/python/mypy/issues/12858)
#CDM_T = TypeVar('CDM_T', bound='CustomDeleteActionModel', covariant=True)

class CustomDeleteActionQuerySet(models.QuerySet[type[T]]):
    """Overrides a model's queryset to invoke pre- and post-delete hooks.

    This ensures the pre_delete() and post_delete() methods are called on each object in the queryset.
    """

    @transaction.atomic
    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Runs pre_delete() on each object, bulk deletes the queryset and runs post_delete() on each object.

        Args:
            *args: Positional arguments passed to super().delete().
            **kwargs: Keyword arguments, for reference check, and passed to super().delete().

        Returns:
            tuple[int, dict[str, int]]: A tuple of:
                a) the total number of objects deleted and
                b) a dictionary with the model name and the count.
        """
        # Pre-delete actions
        # create a copy of the models in the queryset for post-delete actions since it is cleared during the delete
        obj_set = set()
        for obj in self:
            obj_set.add(obj)
            obj.pre_delete()
        # Perform the actual deletion
        count = super().delete(*args, **kwargs)
        # Post-delete actions
        for obj in obj_set:
            obj.post_delete()
        return count


class CustomDeleteActionManager(models.Manager[T]):
    """Default manager for CustomDeleteActionModel.

    It ensures the CustomDeleteActionQuerySet is the default queryset.
    """

    def get_queryset(self) -> CustomDeleteActionQuerySet[type[T]]:
        """Return the queryset with individual delete."""
        return CustomDeleteActionQuerySet(self.model, using=self._db)


class CustomDeleteActionModel(models.Model):
    """Model that provides the pre_delete() and post_delete() methods to implement custom deletion logic.

    It uses a custom manager to ensure the methods are called both on individual and bulk (queryset) deletes.
    """

    objects: CustomDeleteActionManager[T] = CustomDeleteActionManager[T]()

    class Meta:
        """Meta options for the CustomDeleteActionModel."""
        abstract = True

    def pre_delete(self) -> None:
        """Pre-delete hook for custom logic before actual deletion.

        This can for example be used to check if deletion prerequisites are met.
        """

    def post_delete(self) -> None:
        """Post-delete hook for custom logic after actual deletion.

        This can for example be used to clean up orphaned related objects.
        Keep in mind the model is no longer in the database at the time this function is called.
        """

    @final
    @transaction.atomic
    def delete(self, *args: Any, **kwargs: Any) -> tuple[int, dict[str, int]]:
        """Delete the object and run pre_delete() and post_delete() hooks."""
        self.pre_delete()
        count = super().delete(*args, **kwargs)
        self.post_delete()
        return count
