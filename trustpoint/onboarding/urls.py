"""URL patterns for the onboarding app.

TODO Contains API endpoints as well, this should be moved to a separate API app managed by e.g. Django Ninja.
"""

from django.urls import path

from . import views

app_name = 'onboarding'
urlpatterns = [
    path('<int:device_id>/', views.onboarding_manual, name='manual-client'),
    path('exit/<int:pk>/', views.OnboardingExitView.as_view(), name='exit'),
    path('revoke/<int:pk>/', views.OnboardingRevocationView.as_view(), name='revoke'),
    # duplicate required due to trailing slash not being added automatically for POST and cURL requests
    path('api/trust-store/<str:url_ext>/', views.TrustStoreView.as_view(), name='api-trust_store'),
    path('api/trust-store/<str:url_ext>', views.TrustStoreView.as_view(), name='api-trust_store-noslash'),
    path('api/ldevid/cert-chain/<str:url_ext>/', views.cert_chain, name='api-cert_chain'),
    path('api/ldevid/cert-chain/<str:url_ext>', views.cert_chain, name='api-cert_chain-noslash'),
    path('api/ldevid/<str:url_ext>/', views.ldevid, name='api-ldevid'),
    path('api/ldevid/<str:url_ext>', views.ldevid, name='api-ldevid-noslash'),
    path('api/state/<str:url_ext>/', views.state, name='api-state'),
    path('api/state/<str:url_ext>', views.state, name='api-state-noslash'),
]
