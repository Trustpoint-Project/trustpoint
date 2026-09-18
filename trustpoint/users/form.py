# Copyright (c) 2026 The Trustpoint Project Authors
# SPDX-License-Identifier: MIT

"""Forms for creating and updating Trustpoint users and managing groups."""

from typing import Any, ClassVar, cast
from zoneinfo import available_timezones

from django import forms
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm, UserCreationForm
from django.contrib.auth.models import Group, Permission
from django.utils.translation import gettext_lazy as _

from management.models.organization import OrganizationModel
from users.permissions import AppPermissions

from .models import BuiltinRole, GroupProfile, TrustpointUser


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
        fields = (
            *UserCreationForm.Meta.fields,
            'first_name',
            'last_name',
            'email',
            'role',
            'organization',
            'must_change_password',
        )

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to every field widget."""
        super().__init__(*args, **kwargs)
        self.fields['first_name'].required = False
        self.fields['first_name'].label = _('First name (optional)')
        self.fields['last_name'].required = False
        self.fields['last_name'].label = _('Last name (optional)')
        self.fields['email'].required = False
        self.fields['email'].label = _('Email (optional)')
        self.fields['must_change_password'].label = _('Require password change on next login')
        self.fields['must_change_password'].widget.attrs['class'] = 'form-check-input'
        role_field = cast('forms.ModelChoiceField[Group]', self.fields['role'])
        role_field.queryset = Group.objects.exclude(name=BuiltinRole.SERVICE.value)
        organization_field = cast('forms.ModelChoiceField[OrganizationModel]', self.fields['organization'])
        organization_field.required = False
        organization_field.queryset = OrganizationModel.objects.all()
        organization_field.empty_label = _('No organization')
        for field in self.fields.values():
            if field.widget.input_type != 'checkbox':
                field.widget.attrs['class'] = 'form-control'


class TrustpointUserProfileForm(forms.ModelForm[TrustpointUser]):
    """Form for editing the authenticated user's profile and preferences."""

    class Meta:
        """Metaclass limiting the form to personal profile and preference fields."""

        model = TrustpointUser
        fields: ClassVar = [
            'first_name',
            'last_name',
            'email',
            'role',
            'organization',
            'language',
            'timezone',
            'date_format',
            'theme',
            'view_mode',
            'date_joined',
        ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply the standard Bootstrap styling and populate permission-aware choices."""
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        self.fields['first_name'].required = False
        self.fields['last_name'].required = False
        self.fields['email'].required = False
        self.fields['date_joined'].label = _('Registration date')
        self.fields['date_joined'].disabled = True

        language_field = cast('forms.TypedChoiceField', self.fields['language'])
        timezone_field = cast('forms.TypedChoiceField', self.fields['timezone'])
        date_format_field = cast('forms.TypedChoiceField', self.fields['date_format'])
        theme_field = cast('forms.TypedChoiceField', self.fields['theme'])
        view_mode_field = cast('forms.TypedChoiceField', self.fields['view_mode'])

        language_field.choices = TrustpointUser.LanguageChoices.choices
        timezone_field.choices = sorted((tz, tz) for tz in available_timezones())
        date_format_field.choices = TrustpointUser.DateFormatChoices.choices
        theme_field.choices = TrustpointUser.ThemeChoices.choices
        view_mode_field.choices = TrustpointUser.ViewModeChoices.choices
        theme_field.widget.attrs['data-theme-selector'] = 'true'

        can_manage_users = bool(
            self.user and self.user.is_authenticated and self.user.has_perm(AppPermissions.MANAGE_USERS)
        )
        if not can_manage_users:
            self.fields['role'].disabled = True
            self.fields['organization'].disabled = True
        elif (
            self.instance.role.name == BuiltinRole.ADMIN
            and TrustpointUser.objects.filter(role__name=BuiltinRole.ADMIN).count() == 1
        ):
            self.fields['role'].disabled = True

        role_field = self.fields.get('role')
        if role_field is not None:
            role_model_field = cast('forms.ModelChoiceField[Group]', role_field)
            role_model_field.queryset = Group.objects.exclude(name=BuiltinRole.SERVICE.value)
            role_field.widget.attrs['class'] = 'form-select'

        organization_field = self.fields.get('organization')
        if organization_field is not None:
            organization_field.required = False
            organization_model_field = cast('forms.ModelChoiceField[OrganizationModel]', organization_field)
            organization_model_field.queryset = OrganizationModel.objects.all()
            organization_model_field.empty_label = _('No organization')
            organization_field.widget.attrs['class'] = 'form-select'

        for field in self.fields.values():
            if not hasattr(field.widget, 'input_type') or field.widget.input_type != 'checkbox':
                field.widget.attrs['class'] = 'form-control'


class TrustpointPasswordChangeForm(PasswordChangeForm):
    """Form for changing a user's password after verifying the current password."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply the standard Bootstrap styling to password fields."""
        super().__init__(*args, **kwargs)
        self.fields['old_password'].label = _('Current password')
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'

    def clean_new_password1(self) -> str:
        """Require the new password to differ from the current password."""
        new_password = cast('str', self.cleaned_data['new_password1'])
        old_password = self.cleaned_data.get('old_password')
        if old_password and new_password == old_password:
            raise forms.ValidationError(_('The new password must differ from the current password.'))
        return new_password


class TrustpointPasswordSetForm(SetPasswordForm[TrustpointUser]):
    """Form for authorized managers to set another user's password."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply the standard Bootstrap styling to password fields."""
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = 'form-control'


class TrustpointUserRoleForm(forms.ModelForm[TrustpointUser]):
    """Form for changing a user's role and optional organization."""

    class Meta:
        """Metaclass limiting the form to role and organization fields."""

        model = TrustpointUser
        fields: ClassVar = ['first_name', 'last_name', 'email', 'role', 'organization']

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Apply Bootstrap form-control class to role and organization widgets."""
        super().__init__(*args, **kwargs)
        self.fields['first_name'].required = False
        self.fields['first_name'].label = _('First name (optional)')
        self.fields['last_name'].required = False
        self.fields['last_name'].label = _('Last name (optional)')
        self.fields['email'].required = False
        self.fields['email'].label = _('Email (optional)')
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
