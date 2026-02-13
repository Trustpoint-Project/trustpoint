"""Database model utilities for Trustpoint."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, final

from django.db import models, transaction

if TYPE_CHECKING:
    from collections.abc import Iterable

    _ModelBase = models.Model
else:
    _ModelBase = object


__all__ = [
    'CustomDeleteActionManager',
    'CustomDeleteActionModel',
    'CustomDeleteActionQuerySet',
]


class CustomDeleteActionManager[T: 'CustomDeleteActionModel'](models.Manager[T]):
    """Default manager for CustomDeleteActionModel.

    It ensures the CustomDeleteActionQuerySet is the default queryset.
    """

    def get_queryset(self) -> CustomDeleteActionQuerySet[T, T]:
        """Return the queryset with individual delete."""
        return CustomDeleteActionQuerySet(self.model, using=self._db)


class CustomDeleteActionModel(models.Model):
    """Model that provides the pre_delete() and post_delete() methods to implement custom deletion logic.

    It uses a custom manager to ensure the methods are called both on individual and bulk (queryset) deletes.

    """

    objects = CustomDeleteActionManager()

    class Meta:
        """Metaclass configuration."""

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


class CustomDeleteActionQuerySet[MDL: CustomDeleteActionModel, ROW: CustomDeleteActionModel](models.QuerySet[MDL, ROW]):
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
        # create a copy of the models in the queryset for post-delete actions since it is cleared during the deletion
        del args
        del kwargs

        obj_set: set[ROW] = set()
        for obj in self:
            obj_set.add(obj)
            obj.pre_delete()
        # Perform the actual deletion
        count = super().delete()
        # Post-delete actions
        for obj in obj_set:
            obj.post_delete()
        return count


class OrphanDeletionMixin(_ModelBase):
    """Mixin for referenced models that should be deleted after their referenced object is deleted.

    This mixin does not implicitly check for remaining references and always tries to delete the object.
    Therefore, it shall only be used when ALL references to the object either
    a) use on_delete=models.PROTECT (which will prevent deletion of the object if it is still referenced) or
    b) are ok with the reference being deleted even if not strictly orphaned
        (e.g. any remaining referencing object with on_delete=models.CASCADE will also be deleted).
    c) the reference is explicitly listed to be checked
        (by adding it to the "check_references_on_delete" class attribute tuple in the model class).
    """

    check_references_on_delete: tuple[str, ...] | None = None

    @classmethod
    def delete_if_orphaned(cls, instance: OrphanDeletionMixin | None) -> None:
        """Removes the model instance if no longer referenced.

        This method checks if the referenced object is still referenced by other objects
        and only deletes it if it is not.
        The related fields to check for remaining references can be specified
        in the class attribute tuple check_references_on_delete.
        It is only necessary to check fields that are not protected (e.g. ManyToManyField).

        Args:
            instance: The instance to check and delete if orphaned.
        """
        if not instance or not instance.pk:
            return
        if instance.check_references_on_delete:
            for rel in instance.check_references_on_delete:
                rel_qs = getattr(instance, rel)
                if rel_qs and rel_qs.exists():
                    return
        try:
            instance.delete()
        except models.ProtectedError:
            return

    @classmethod
    def multi_delete_if_orphaned(cls, instance_pks: Iterable[int] | None) -> None:
        """Deletes multiple model instances by PK if no longer referenced."""
        if not instance_pks:
            return

        for instance in instance_pks:
            cls.delete_if_orphaned(cls.objects.filter(pk=instance).first())  # type: ignore[attr-defined]
