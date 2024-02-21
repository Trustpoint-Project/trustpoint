"""Contains some global views that are not specific to a single app.

This module contains some general redirect and error views (e.g. 404) as well as specific mixins and view classes
which can be used within the apps.
"""

from typing import Any, Callable

from django.views.generic.base import RedirectView, ContextMixin


from django import forms as dj_forms
from django.views.generic.base import View, TemplateResponseMixin
from django.http import HttpResponseRedirect, HttpRequest

# from django.utils.functional import Promise
from django.shortcuts import render


class IndexView(RedirectView):
    """View that redirects to the index home page."""

    permanent: bool = True
    pattern_name: str = 'home:dashboard'


class PageContextDataMixin(ContextMixin):
    page_category: str | None = None
    page_name: str | None = None

    def get_context_data(self, **kwargs: Any) -> dict:
        """Adds page_category and page_name for the PKI -> Issuing CAs."""

        if 'page_category' not in kwargs and self.page_category is not None:
            kwargs['page_category'] = self.page_category
        if 'page_name' not in kwargs and self.page_name is not None:
            kwargs['page_name'] = self.page_name
        return super().get_context_data(**kwargs)


class Form:
    """Form wrapper for multi form views."""

    _form_name: str
    _initial: dict = {}
    _form_class: type
    _success_url: Callable | str | None = None
    _prefix: str | None = None

    def __init__(
        self, form_name: str, form_class: type, success_url: str, initial: dict | None = None, prefix: str | None = None
    ):
        self.form_name = form_name
        self.form_class = form_class
        self.success_url = success_url
        if initial is None:
            initial = {}
        self.initial = initial
        self.prefix = prefix

    @property
    def form_name(self) -> str:
        return self._form_name

    @form_name.setter
    def form_name(self, form_name: str) -> None:
        form_name = str(form_name)
        if not form_name:
            raise ValueError('form_name cannot be an empty string.')
        self._form_name = form_name

    @property
    def initial(self) -> dict:
        return self._initial

    @initial.setter
    def initial(self, initial: dict) -> None:
        if not isinstance(initial, dict):
            raise TypeError(f'initial must be a dictionary, but found {type(initial)}.')
        self._initial = initial

    @initial.deleter
    def initial(self) -> None:
        self._initial = {}

    @property
    def form_class(self) -> type:
        return self._form_class

    @form_class.setter
    def form_class(self, form_class: type) -> None:
        if not issubclass(form_class, dj_forms.Form):
            raise TypeError(f'form_class must be a subclass of django.forms.Forms.')
        self._form_class = form_class

    @property
    def success_url(self) -> str | None:
        return self._success_url

    @success_url.setter
    def success_url(self, success_url: Any) -> None:
        self._success_url = success_url

    @success_url.deleter
    def success_url(self) -> None:
        self._success_url = None

    @property
    def prefix(self) -> str | None:
        return self._prefix

    @prefix.setter
    def prefix(self, prefix: str | None) -> None:
        if prefix is not None:
            if not isinstance(prefix, str):
                raise TypeError(f'prefix must be a string or None, but found {type(prefix)}.')
            if not prefix:
                raise ValueError('prefix cannot be an empty string.')
        self._prefix = prefix

    @prefix.deleter
    def prefix(self) -> None:
        self._prefix = None

    def __str__(self) -> str:
        return f'Form(form_name={self.form_name})'


class MultiFormMixin(ContextMixin):
    _forms: dict[str, Form] = {}
    request: HttpRequest
    render_to_response: Callable
    template_name: str

    def __init__(self, forms: list[Form] | None = None) -> None:
        if forms is not None:
            self.forms = forms

    def _get_form(self, form_name: str) -> Form:
        form = self.forms.get(form_name, None)
        if form is None:
            raise ValueError(f'Form with form_name {form_name} does not exist.')
        return form

    @property
    def forms(self) -> dict[str, Form]:
        return self._forms

    @forms.setter
    def forms(self, forms: dict[str, Form]) -> None:
        if not isinstance(forms, dict):
            raise TypeError(f'forms must be a dictionary, but found {type(forms)}.')
        for key, form in forms.items():
            if not isinstance(form, Form):
                raise TypeError(f'forms contains at least one form that is not of type Form, but of type {type(form)}.')
        self._forms = forms

    @forms.deleter
    def forms(self) -> None:
        self._forms = {}

    def add_form(self, form: Form) -> None:
        if not isinstance(form, Form):
            raise TypeError(f'form must be a Form, but found {type(form)}.')
        self._forms[form.form_name] = form

    def get_initial(self, form_name: str) -> dict:
        """Return the initial data to use for the form specified by form_name."""
        return self._get_form(form_name).initial

    def get_prefix(self, form_name: str) -> str | None:
        """Return the prefix to use for the form specified by form_name."""
        return self._get_form(form_name).prefix

    def get_form_class(self, form_name: str) -> type:
        """Return the form class to use for the form specified by form_name."""
        return self._get_form(form_name).form_class

    def get_form(self, form_name: str) -> dj_forms.Form:
        """Return an instance of the form specified by form_name."""
        return self._get_form(form_name).form_class(**self.get_form_kwargs(form_name))

    def get_new_form(self, form_name: str) -> dj_forms.Form:
        return self._get_form(form_name).form_class()

    def get_form_kwargs(self, form_name: str) -> dict:
        """Return the keyword arguments for instantiating the form specified by form_name."""
        form = self._get_form(form_name)
        kwargs = {
            'initial': form.initial,
            'prefix': form.prefix,
        }

        if self.request.method in ('POST', 'PUT'):
            kwargs.update(
                {
                    'data': self.request.POST,
                    'files': self.request.FILES,
                }
            )
        return kwargs

    def get_success_url(self, form_name: str) -> str:
        """Return the URL to redirect to after processing a valid form specified by form_name."""
        return str(self._get_form(form_name).success_url)

    def form_valid(self, form_name: str, form, request):
        """If the form is valid, redirect to the supplied URL."""
        form_valid_hook = getattr(self, f'on_valid_form_{form_name}', None)
        if form_valid_hook:
            form_valid_hook(form, request)
        return HttpResponseRedirect(self._get_form(form_name).success_url)

    def form_invalid(self, request, form_name: str, form):
        """If the form is invalid, render the invalid form."""
        return self.render_to_response(self.get_context_data(form_name=form_name, form=form))

    def get_context_data(self, form_name=None, form=None, **kwargs):
        """Insert the forms into the context dict."""
        if form_name and form:
            kwargs[form_name] = form
        for fn, form in self.forms.items():
            if fn != form_name:
                kwargs[fn] = self.get_new_form(fn)
        return super().get_context_data(**kwargs)


class MultiFormView(TemplateResponseMixin, MultiFormMixin, View):
    """Render all forms on GET and processes the form specified by form_name on POST."""

    def get(self, request, *args, **kwargs):
        """Handle GET requests: instantiate a blank version of the form."""
        return self.render_to_response(self.get_context_data())

    def post(self, request, *args, **kwargs):
        for form_name in self.forms:
            if form_name in request.POST or form_name.replace('_', '-') in request.POST:
                current_form_name = form_name
                break
        else:
            # TODO(Alex): msg
            return self.render_to_response(self.get_context_data())

        form = self.get_form(current_form_name)
        if form.is_valid():
            return self.form_valid(current_form_name, form, request)
        else:
            return self.form_invalid(request, form_name, form)
