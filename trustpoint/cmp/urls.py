"""URLs for the Django CMP Application."""

from django.urls import path

from cmp.views import CmpRequestView

app_name = 'cmp'

urlpatterns = [
    # Previous URLs for demos, not compliant with RFC 9480 section 3.3
    path('initialization/<str:domain>', CmpRequestView.as_view(), name='initialization_old'),
    path('initialization/<str:domain>/', CmpRequestView.as_view(), name='initialization_old_slash'),
    # End of previous demo URLs
    # empty (.well-known/cmp) URLs for any operation
    path('', CmpRequestView.as_view(), name='req'),
    # operation specified in URL, no path segments for domain or profile
    path('<str:operation>', CmpRequestView.as_view(), name='req_op'),
    path('<str:operation>/', CmpRequestView.as_view(), name='req_op_slash'),
    # single path seg, only profile specified in URL
    path('p/~<str:cert_profile>', CmpRequestView.as_view(), name='req_td_profile'),
    path('p/~<str:cert_profile>/', CmpRequestView.as_view(), name='req_td_profile_slash'),
    # 2 path segs, profile and operation specified in URL
    path('p/~<str:cert_profile>/<str:operation>', CmpRequestView.as_view(), name='req_td_profile_op'),
    path('p/~<str:cert_profile>/<str:operation>/', CmpRequestView.as_view(), name='req_td_profile_op_slash'),
    # single path seg, domain and profile specified in URL, no operation
    path('p/<str:domain>~<str:cert_profile>', CmpRequestView.as_view(), name='req_domain_td_profile'),
    path('p/<str:domain>~<str:cert_profile>/', CmpRequestView.as_view(), name='req_domain_td_profile_slash'),
    # single path seg, domain specified in URL, no profile or operation
    path('p/<str:domain>', CmpRequestView.as_view(), name='req_domain'),
    path('p/<str:domain>/', CmpRequestView.as_view(), name='req_domain_slash'),
    # 2 path segs, either domain and profile specified in URL, no operation (/p/domain/profile)
    # OR domain and operation specified in URL, no profile (/p/domain/operation)
    # OR /p/domain~profile/operation
    path(
        'p/<str:domain>~<str:cert_profile>/<str:operation>', CmpRequestView.as_view(), name='req_domain_td_profile_op'
    ),
    path(
        'p/<str:domain>~<str:cert_profile>/<str:operation>/',
        CmpRequestView.as_view(),
        name='req_domain_td_profile_op_slash',
    ),
    path('p/<str:domain>/<str:cert_profile_or_operation>', CmpRequestView.as_view(), name='req_domain_profile_or_op'),
    path(
        'p/<str:domain>/<str:cert_profile_or_operation>/',
        CmpRequestView.as_view(),
        name='req_domain_profile_or_op_slash',
    ),
    # 3 path segs, domain, profile, and operation specified in URL (/p/domain/profile/operation)
    path('p/<str:domain>/<str:cert_profile>/<str:operation>', CmpRequestView.as_view(), name='req_domain_profile_op'),
    path(
        'p/<str:domain>/<str:cert_profile>/<str:operation>/',
        CmpRequestView.as_view(),
        name='req_domain_profile_op_slash',
    ),
]
