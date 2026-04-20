"""Forms for creating and updating Trustpoint users and managing groups."""

from typing import Any, ClassVar

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import Group, Permission
from django.utils.translation import gettext_lazy as _

from .models import GroupProfile, TrustpointUser


class TrustpointUserCreationForm(UserCreationForm[TrustpointUser]):
    """Form for creating a new TrustpointUser with an explicit role selection.

    The ``role`` field is rendered as a dropdown listing every available
    ``Group`` instance.
    """

    class Meta(UserCreationForm.Meta):
        """Metaclass extending the standard UserCreationForm with the role field."""

        model = TrustpointUser
        fields = (*UserCreationForm.Meta.fields, 'role')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to every field widget."""
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class TrustpointUserRoleForm(forms.ModelForm[TrustpointUser]):
    """Minimal form for changing a user's role only."""

    class Meta:
        """Metaclass limiting the form to the role field."""

        model = TrustpointUser
        fields: ClassVar = ['role']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to the role widget."""
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class _PermissionMultipleChoiceField(forms.ModelMultipleChoiceField[Permission]):
    """Custom field that formats permission labels as ``app | model | name``."""

    def label_from_instance(self, obj: Permission) -> str:
        """Return a human-readable label for a single permission.

        Args:
            obj: The ``Permission`` instance to label.

        Returns:
            A string formatted as ``'app_label | model | permission name'``.
        """
        ct = obj.content_type
        return f'{ct.app_label} | {ct.model} | {obj.name}'


class GroupPermissionForm(forms.ModelForm[Group]):
    """Form for creating or editing a Django Group with permissions.

    Uses a custom ``permissions`` field that orders permissions by
    app / model and renders labels in ``app | model | name`` format.
    The dual-listbox JavaScript in the template handles the interactive
    selection UI.

    The ``grants_staff`` and ``grants_superuser`` checkboxes are stored
    on the related :class:`~users.models.GroupProfile` and control
    which Django flags users assigned to this group receive.
    """

    permissions = _PermissionMultipleChoiceField(
        queryset=Permission.objects.select_related('content_type').order_by(
            'content_type__app_label',
            'content_type__model',
            'codename',
        ),
        required=False,
        widget=forms.SelectMultiple(attrs={'class': 'form-select', 'size': '15'}),
        label=_('Permissions'),
    )

    grants_staff = forms.BooleanField(
        required=False,
        label=_('Staff status'),
        help_text=_('Users with this role can log into the admin site.'),
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    grants_superuser = forms.BooleanField(
        required=False,
        label=_('Superuser status'),
        help_text=_('Users with this role have all permissions without explicitly assigning them.'),
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
    )

    class Meta:
        """Metaclass for GroupPermissionForm."""

        model = Group
        fields: ClassVar = ['name', 'permissions']
        widgets: ClassVar = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Pre-populate the staff/superuser checkboxes from the GroupProfile."""
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            profile: GroupProfile | None = getattr(self.instance, 'profile', None)
            if profile:
                self.fields['grants_staff'].initial = profile.grants_staff
                self.fields['grants_superuser'].initial = profile.grants_superuser

    def save(self, *, commit: bool = True) -> Group:  # type: ignore[override]
        """Save the Group and create or update its GroupProfile.

        Args:
            commit: Whether to persist changes to the database.

        Returns:
            The saved Group instance.
        """
        group = super().save(commit=commit)
        if commit:
            GroupProfile.objects.update_or_create(
                group=group,
                defaults={
                    'grants_staff': self.cleaned_data['grants_staff'],
                    'grants_superuser': self.cleaned_data['grants_superuser'],
                },
            )
        return group
