from django.shortcuts import render
from trustpoint.views.base import ContextDataMixin, SortableTableMixin
from django.contrib.auth import get_user_model
from django.views.generic import ListView


class UserContextMixin(ContextDataMixin):
    """Mixin which adds context_data for the User -> User management page."""
    context_page_category = 'management'
    context_page_name = 'user_management'

class UserTableView(UserContextMixin, SortableTableMixin, ListView):
    model = get_user_model()
    


def user(request):
    return render(request, 'management/user_management.html')
