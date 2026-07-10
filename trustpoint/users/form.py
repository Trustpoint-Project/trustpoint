"""Forms for creating and updating Trustpoint users and managing groups."""

from typing import Any, ClassVar, cast

from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import Group, Permission
from django.utils.translation import gettext_lazy as _

from management.models.organization import OrganizationModel

from .models import GroupProfile, TrustpointUser


class TrustpointSuperUserCreationForm(UserCreationForm[TrustpointUser]):
    """Form for creating the initial superuser during setup.

    This form is used in the setup wizard to create the first superuser.
    """

    class Meta(UserCreationForm.Meta):
        """Metaclass extending the standard UserCreationForm with the TrustpointUser model."""

        model = TrustpointUser
        fields = UserCreationForm.Meta.fields

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to every field widget."""
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class TrustpointUserCreationForm(UserCreationForm[TrustpointUser]):
    """Form for creating a new TrustpointUser with an explicit role selection.

    The ``role`` and optional ``organization`` fields are rendered as
    dropdowns listing every available Group / Organization.
    """

    class Meta(UserCreationForm.Meta):
        """Metaclass extending the standard UserCreationForm with the role field."""

        model = TrustpointUser
        fields = (*UserCreationForm.Meta.fields, 'role', 'organization')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to every field widget."""
        super().__init__(*args, **kwargs)
        organization_field = cast('forms.ModelChoiceField[OrganizationModel]', self.fields['organization'])
        organization_field.required = False
        organization_field.queryset = OrganizationModel.objects.all()
        organization_field.empty_label = _('No organization')
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class TrustpointUserRoleForm(forms.ModelForm[TrustpointUser]):
    """Form for changing a user's role and optional organization."""

    class Meta:
        """Metaclass limiting the form to role and organization fields."""

        model = TrustpointUser
        fields: ClassVar = ['role', 'organization']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to role and organization widgets."""
        super().__init__(*args, **kwargs)
        organization_field = cast('forms.ModelChoiceField[OrganizationModel]', self.fields['organization'])
        organization_field.required = False
        organization_field.queryset = OrganizationModel.objects.all()
        organization_field.empty_label = _('No organization')
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class _PermissionMultipleChoiceField(forms.ModelMultipleChoiceField[Permission]):
    """Custom field that formats permission labels as ``app | model | name``."""

    def label_from_instance(self, obj: Permission) -> str:
        """Return a human-readable label for a single permission.

        Args:
            obj: The ``Permission`` instance to label.

        Returns:
            A string formatted as ``'permission name'``.
        """
        return f'{obj.name}'


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
        queryset=Permission.objects.select_related('content_type').filter(
             content_type__model='apppermission'
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
