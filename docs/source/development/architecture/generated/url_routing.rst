URL Routing Map
===============

This document maps URL patterns to their corresponding views across the Trustpoint application.

URL Patterns by App
-------------------


Aoki
^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``aoki/init/``
     - ``view``
     - ``aoki_init``


Cmp
^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``.well-known/cmp/``
     - ``view``
     - ``req``
   * - ``.well-known/cmp/<str:operation>``
     - ``view``
     - ``req_op``
   * - ``.well-known/cmp/<str:operation>/``
     - ``view``
     - ``req_op_slash``
   * - ``.well-known/cmp/initialization/<str:domain>``
     - ``view``
     - ``initialization_old``
   * - ``.well-known/cmp/initialization/<str:domain>/``
     - ``view``
     - ``initialization_old_slash``
   * - ``.well-known/cmp/p/<str:domain>``
     - ``view``
     - ``req_domain``
   * - ``.well-known/cmp/p/<str:domain>/``
     - ``view``
     - ``req_domain_slash``
   * - ``.well-known/cmp/p/<str:domain>/<str:cert_profile>/<str:operation>``
     - ``view``
     - ``req_domain_profile_op``
   * - ``.well-known/cmp/p/<str:domain>/<str:cert_profile>/<str:operation>/``
     - ``view``
     - ``req_domain_profile_op_slash``
   * - ``.well-known/cmp/p/<str:domain>/<str:cert_profile_or_operation>``
     - ``view``
     - ``req_domain_profile_or_op``
   * - ``.well-known/cmp/p/<str:domain>/<str:cert_profile_or_operation>/``
     - ``view``
     - ``req_domain_profile_or_op_slash``
   * - ``.well-known/cmp/p/<str:domain>~<str:cert_profile>``
     - ``view``
     - ``req_domain_td_profile``
   * - ``.well-known/cmp/p/<str:domain>~<str:cert_profile>/``
     - ``view``
     - ``req_domain_td_profile_slash``
   * - ``.well-known/cmp/p/<str:domain>~<str:cert_profile>/<str:operation>``
     - ``view``
     - ``req_domain_td_profile_op``
   * - ``.well-known/cmp/p/<str:domain>~<str:cert_profile>/<str:operation>/``
     - ``view``
     - ``req_domain_td_profile_op_slash``
   * - ``.well-known/cmp/p/~<str:cert_profile>``
     - ``view``
     - ``req_td_profile``
   * - ``.well-known/cmp/p/~<str:cert_profile>/``
     - ``view``
     - ``req_td_profile_slash``
   * - ``.well-known/cmp/p/~<str:cert_profile>/<str:operation>``
     - ``view``
     - ``req_td_profile_op``
   * - ``.well-known/cmp/p/~<str:cert_profile>/<str:operation>/``
     - ``view``
     - ``req_td_profile_op_slash``


Devices
^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/^devices/$``
     - ``DeviceViewSet``
     - ``device-list``
   * - ``api/^devices/(?P<pk>[^/.]+)/$``
     - ``DeviceViewSet``
     - ``device-detail``
   * - ``api/^devices/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``DeviceViewSet``
     - ``device-detail``
   * - ``api/^devices\.(?P<format>[a-z0-9]+)/?$``
     - ``DeviceViewSet``
     - ``device-list``
   * - ``devices/``
     - ``view``
     - ``devices``
   * - ``devices/^delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_delete``
   * - ``devices/^opc-ua-gds-push/delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_delete``
   * - ``devices/^opc-ua-gds-push/revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_revoke``
   * - ``devices/^opc-ua-gds/delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``opc_ua_gds_device_delete``
   * - ``devices/^opc-ua-gds/revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``opc_ua_gds_device_revoke``
   * - ``devices/^revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_revoke``
   * - ``devices/^zero-touch-credentials/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``zero_touch_credentials-delete_confirm``
   * - ``devices/browser/``
     - ``view``
     - ``browser_login``
   * - ``devices/browser/credential-download/<int:pk>/``
     - ``view``
     - ``browser_domain_credential_download``
   * - ``devices/certificate-lifecycle-management/<int:pk>/``
     - ``view``
     - ``devices_certificate_lifecycle_management``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/``
     - ``view``
     - ``devices_no_onboarding_clm_issue_application_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cmp-shared-secret/``
     - ``view``
     - ``devices_no_onboarding_cmp_shared_secret_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/est-username-password/``
     - ``view``
     - ``devices_no_onboarding_est_username_password_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/profile/<int:profile_id>/``
     - ``view``
     - ``devices_certificate_lifecycle_management_issue_profile_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/select-certificate-profile``
     - ``view``
     - ``devices_no_onboarding_select_certificate_profile``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/rest-username-password/``
     - ``view``
     - ``devices_no_onboarding_rest_username_password_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/cmp-domain-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential_cmp_domain_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/est-domain-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential_est_domain_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/rest-domain-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential_rest_domain_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/cmp-shared-secret/``
     - ``view``
     - ``devices_certificate_lifecycle_management_issue_domain_credential_cmp_shared_secret``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/est-username-password/``
     - ``view``
     - ``devices_certificate_lifecycle_management_issue_domain_credential_est_username_password``
   * - ``devices/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/rest-username-password/``
     - ``view``
     - ``devices_certificate_lifecycle_management_issue_domain_credential_rest_username_password``
   * - ``devices/certificate/download/<int:pk>/``
     - ``view``
     - ``devices_certificate-download``
   * - ``devices/create/``
     - ``view``
     - ``devices_create``
   * - ``devices/create/no-onboarding/``
     - ``view``
     - ``devices_create_no_onboarding``
   * - ``devices/create/onboarding/``
     - ``view``
     - ``devices_create_onboarding``
   * - ``devices/create/opc-ua-gds-push/``
     - ``view``
     - ``devices_create_opc_ua_gds_push``
   * - ``devices/credential-download/browser/<int:pk>/``
     - ``view``
     - ``devices_browser_otp_view``
   * - ``devices/credential-download/browser/<int:pk>/cancel``
     - ``view``
     - ``devices_browser_cancel``
   * - ``devices/credential-download/browser/<int:pk>/cancel``
     - ``view``
     - ``opc_ua_gds_browser_cancel``
   * - ``devices/credential/download/<int:pk>/``
     - ``view``
     - ``devices_credential-download``
   * - ``devices/download/<int:pk>/``
     - ``view``
     - ``devices_download``
   * - ``devices/new-onboarding/``
     - ``view``
     - ``devices_new_onboarding``
   * - ``devices/opc-ua-gds-push/<int:pk>/cert-renewal-settings/``
     - ``view``
     - ``devices_cert_renewal_settings``
   * - ``devices/opc-ua-gds-push/<int:pk>/update-server-certificate/``
     - ``view``
     - ``devices_update_server_certificate``
   * - ``devices/opc-ua-gds-push/<int:pk>/update-trustlist/``
     - ``view``
     - ``devices_update_trustlist``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_push_certificate_lifecycle_management``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/discover-server/``
     - ``view``
     - ``devices_discover_server``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/est-domain-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential_est_domain_credential``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/opc-ua-gds-push-domain-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_application_credential_opc_ua_gds_push_domain_credential``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/``
     - ``view``
     - ``devices_onboarding_clm_issue_domain_credential``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/onboarding/truststore-associated/``
     - ``view``
     - ``devices_onboarding_truststore_associated_help``
   * - ``devices/opc-ua-gds-push/certificate-lifecycle-management/<int:pk>/truststore-association/``
     - ``view``
     - ``devices_truststore_association``
   * - ``devices/opc-ua-gds-push/certificate/download/<int:pk>/``
     - ``view``
     - ``devices_certificate-download``
   * - ``devices/opc-ua-gds-push/create/``
     - ``view``
     - ``opc_ua_gds_push_create_redirect``
   * - ``devices/opc-ua-gds-push/create/onboarding``
     - ``view``
     - ``opc_ua_gds_push_create_onboarding_redirect``
   * - ``devices/opc-ua-gds-push/credential/download/<int:pk>/``
     - ``view``
     - ``devices_credential-download``
   * - ``devices/opc-ua-gds-push/download/<int:pk>/``
     - ``view``
     - ``devices_download``
   * - ``devices/opc-ua-gds-push/revoke/<int:pk>/``
     - ``view``
     - ``devices_credential_revoke``
   * - ``devices/opc-ua-gds/``
     - ``view``
     - ``opc_ua_gds``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_certificate_lifecycle_management``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/``
     - ``view``
     - ``opc_ua_gds_no_onboarding_clm_issue_application_credential``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cmp-shared-secret/``
     - ``view``
     - ``opc_ua_gds_no_onboarding_cmp_shared_secret_help``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/est-username-password/``
     - ``view``
     - ``opc_ua_gds_no_onboarding_est_username_password_help``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/profile/<int:profile_id>/``
     - ``view``
     - ``opc_ua_gds_certificate_lifecycle_management_issue_profile_credential``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/select-certificate-profile``
     - ``view``
     - ``opc_ua_gds_no_onboarding_select_certificate_profile``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/rest-username-password/``
     - ``view``
     - ``opc_ua_gds_no_onboarding_rest_username_password_help``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/``
     - ``view``
     - ``opc_ua_gds_onboarding_clm_issue_application_credential``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/cmp-domain-credential/``
     - ``view``
     - ``opc_ua_gds_onboarding_clm_issue_application_credential_cmp_domain_credential``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/est-domain-credential/``
     - ``view``
     - ``opc_ua_gds_onboarding_clm_issue_application_credential_est_domain_credential``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-application-credential/rest-domain-credential/``
     - ``view``
     - ``opc_ua_gds_onboarding_clm_issue_application_credential_rest_domain_credential``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/cmp-shared-secret/``
     - ``view``
     - ``opc_ua_gds_certificate_lifecycle_management_issue_domain_credential_cmp_shared_secret``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/est-username-password/``
     - ``view``
     - ``opc_ua_gds_certificate_lifecycle_management_issue_domain_credential_est_username_password``
   * - ``devices/opc-ua-gds/certificate-lifecycle-management/<int:pk>/onboarding/issue-domain-credential/rest-username-password/``
     - ``view``
     - ``opc_ua_gds_certificate_lifecycle_management_issue_domain_credential_rest_username_password``
   * - ``devices/opc-ua-gds/certificate/download/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_certificate-download``
   * - ``devices/opc-ua-gds/create/``
     - ``view``
     - ``opc_ua_gds_create``
   * - ``devices/opc-ua-gds/create/no-onboarding``
     - ``view``
     - ``opc_ua_gds_create_no_onboarding``
   * - ``devices/opc-ua-gds/create/onboarding``
     - ``view``
     - ``opc_ua_gds_create_onboarding``
   * - ``devices/opc-ua-gds/credential-download/browser/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_browser_otp_view``
   * - ``devices/opc-ua-gds/credential/download/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_credential-download``
   * - ``devices/opc-ua-gds/download/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_download``
   * - ``devices/opc-ua-gds/revoke/<int:pk>/``
     - ``view``
     - ``opc_ua_gds_credential_revoke``
   * - ``devices/revoke/<int:pk>/``
     - ``view``
     - ``devices_credential_revoke``
   * - ``devices/trust-bundle-download/<int:pk>/``
     - ``view``
     - ``trust_bundle_download``
   * - ``devices/zero-touch-credentials/``
     - ``view``
     - ``zero_touch_credentials``
   * - ``devices/zero-touch-credentials/<int:owner_pk>/issued-credential/<int:pk>/delete/``
     - ``view``
     - ``zero_touch_credentials-issued-credential-delete``
   * - ``devices/zero-touch-credentials/add/``
     - ``view``
     - ``zero_touch_credentials-add``
   * - ``devices/zero-touch-credentials/add/est/``
     - ``view``
     - ``zero_touch_credentials-add-est``
   * - ``devices/zero-touch-credentials/add/est/no-onboarding/``
     - ``view``
     - ``zero_touch_credentials-add-est-no-onboarding``
   * - ``devices/zero-touch-credentials/add/est/onboarding/``
     - ``view``
     - ``zero_touch_credentials-add-est-onboarding``
   * - ``devices/zero-touch-credentials/add/file-import/``
     - ``view``
     - ``zero_touch_credentials-add-file_import``
   * - ``devices/zero-touch-credentials/aoki-cmp-help/``
     - ``view``
     - ``zero_touch_credentials-aoki_cmp_help``
   * - ``devices/zero-touch-credentials/aoki-demo-download/<str:filename>``
     - ``view``
     - ``zero_touch_credentials-aoki_demo_download``
   * - ``devices/zero-touch-credentials/aoki-est-help/``
     - ``view``
     - ``zero_touch_credentials-aoki_est_help``
   * - ``devices/zero-touch-credentials/aoki-setup-demo-env/``
     - ``view``
     - ``zero_touch_credentials-aoki_setup_demo_env``
   * - ``devices/zero-touch-credentials/clm/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-clm``
   * - ``devices/zero-touch-credentials/define-cert-content-domain-credential-est/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-define-cert-content-domain-credential-est``
   * - ``devices/zero-touch-credentials/define-cert-content-est/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-define-cert-content-est``
   * - ``devices/zero-touch-credentials/details/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-details``
   * - ``devices/zero-touch-credentials/onboarding-setup/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-onboarding-setup``
   * - ``devices/zero-touch-credentials/request-cert-est/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-request-cert-est``
   * - ``devices/zero-touch-credentials/request-domain-credential-est/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-request-domain-credential-est``
   * - ``devices/zero-touch-credentials/truststore-association/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-truststore-association``


Django
^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``^media/(?P<path>.*)$``
     - ``serve``
     - ``-``
   * - ``admin/``
     - ``index``
     - ``index``
   * - ``admin/(?P<url>.*)$``
     - ``catch_all_view``
     - ``-``
   * - ``admin/^(?P<app_label>devices\|onboarding\|pki\|signer\|auth\|django_q\|workflows2)/$``
     - ``app_index``
     - ``app_list``
   * - ``admin/auth/group/``
     - ``changelist_view``
     - ``auth_group_changelist``
   * - ``admin/auth/group/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/auth/group/<path:object_id>/change/``
     - ``change_view``
     - ``auth_group_change``
   * - ``admin/auth/group/<path:object_id>/delete/``
     - ``delete_view``
     - ``auth_group_delete``
   * - ``admin/auth/group/<path:object_id>/history/``
     - ``history_view``
     - ``auth_group_history``
   * - ``admin/auth/group/add/``
     - ``add_view``
     - ``auth_group_add``
   * - ``admin/auth/user/``
     - ``changelist_view``
     - ``auth_user_changelist``
   * - ``admin/auth/user/<id>/password/``
     - ``user_change_password``
     - ``auth_user_password_change``
   * - ``admin/auth/user/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/auth/user/<path:object_id>/change/``
     - ``change_view``
     - ``auth_user_change``
   * - ``admin/auth/user/<path:object_id>/delete/``
     - ``delete_view``
     - ``auth_user_delete``
   * - ``admin/auth/user/<path:object_id>/history/``
     - ``history_view``
     - ``auth_user_history``
   * - ``admin/auth/user/add/``
     - ``add_view``
     - ``auth_user_add``
   * - ``admin/autocomplete/``
     - ``autocomplete_view``
     - ``autocomplete``
   * - ``admin/devices/devicemodel/``
     - ``changelist_view``
     - ``devices_devicemodel_changelist``
   * - ``admin/devices/devicemodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/devices/devicemodel/<path:object_id>/change/``
     - ``change_view``
     - ``devices_devicemodel_change``
   * - ``admin/devices/devicemodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``devices_devicemodel_delete``
   * - ``admin/devices/devicemodel/<path:object_id>/history/``
     - ``history_view``
     - ``devices_devicemodel_history``
   * - ``admin/devices/devicemodel/add/``
     - ``add_view``
     - ``devices_devicemodel_add``
   * - ``admin/devices/remotedevicecredentialdownloadmodel/``
     - ``changelist_view``
     - ``devices_remotedevicecredentialdownloadmodel_changelist``
   * - ``admin/devices/remotedevicecredentialdownloadmodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/devices/remotedevicecredentialdownloadmodel/<path:object_id>/change/``
     - ``change_view``
     - ``devices_remotedevicecredentialdownloadmodel_change``
   * - ``admin/devices/remotedevicecredentialdownloadmodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``devices_remotedevicecredentialdownloadmodel_delete``
   * - ``admin/devices/remotedevicecredentialdownloadmodel/<path:object_id>/history/``
     - ``history_view``
     - ``devices_remotedevicecredentialdownloadmodel_history``
   * - ``admin/devices/remotedevicecredentialdownloadmodel/add/``
     - ``add_view``
     - ``devices_remotedevicecredentialdownloadmodel_add``
   * - ``admin/django_q/failure/``
     - ``changelist_view``
     - ``django_q_failure_changelist``
   * - ``admin/django_q/failure/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/django_q/failure/<path:object_id>/change/``
     - ``change_view``
     - ``django_q_failure_change``
   * - ``admin/django_q/failure/<path:object_id>/delete/``
     - ``delete_view``
     - ``django_q_failure_delete``
   * - ``admin/django_q/failure/<path:object_id>/history/``
     - ``history_view``
     - ``django_q_failure_history``
   * - ``admin/django_q/failure/add/``
     - ``add_view``
     - ``django_q_failure_add``
   * - ``admin/django_q/ormq/``
     - ``changelist_view``
     - ``django_q_ormq_changelist``
   * - ``admin/django_q/ormq/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/django_q/ormq/<path:object_id>/change/``
     - ``change_view``
     - ``django_q_ormq_change``
   * - ``admin/django_q/ormq/<path:object_id>/delete/``
     - ``delete_view``
     - ``django_q_ormq_delete``
   * - ``admin/django_q/ormq/<path:object_id>/history/``
     - ``history_view``
     - ``django_q_ormq_history``
   * - ``admin/django_q/ormq/add/``
     - ``add_view``
     - ``django_q_ormq_add``
   * - ``admin/django_q/schedule/``
     - ``changelist_view``
     - ``django_q_schedule_changelist``
   * - ``admin/django_q/schedule/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/django_q/schedule/<path:object_id>/change/``
     - ``change_view``
     - ``django_q_schedule_change``
   * - ``admin/django_q/schedule/<path:object_id>/delete/``
     - ``delete_view``
     - ``django_q_schedule_delete``
   * - ``admin/django_q/schedule/<path:object_id>/history/``
     - ``history_view``
     - ``django_q_schedule_history``
   * - ``admin/django_q/schedule/add/``
     - ``add_view``
     - ``django_q_schedule_add``
   * - ``admin/django_q/success/``
     - ``changelist_view``
     - ``django_q_success_changelist``
   * - ``admin/django_q/success/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/django_q/success/<path:object_id>/change/``
     - ``change_view``
     - ``django_q_success_change``
   * - ``admin/django_q/success/<path:object_id>/delete/``
     - ``delete_view``
     - ``django_q_success_delete``
   * - ``admin/django_q/success/<path:object_id>/history/``
     - ``history_view``
     - ``django_q_success_history``
   * - ``admin/django_q/success/add/``
     - ``add_view``
     - ``django_q_success_add``
   * - ``admin/jsi18n/``
     - ``i18n_javascript``
     - ``jsi18n``
   * - ``admin/login/``
     - ``login``
     - ``login``
   * - ``admin/logout/``
     - ``logout``
     - ``logout``
   * - ``admin/onboarding/noonboardingconfigmodel/``
     - ``changelist_view``
     - ``onboarding_noonboardingconfigmodel_changelist``
   * - ``admin/onboarding/noonboardingconfigmodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/onboarding/noonboardingconfigmodel/<path:object_id>/change/``
     - ``change_view``
     - ``onboarding_noonboardingconfigmodel_change``
   * - ``admin/onboarding/noonboardingconfigmodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``onboarding_noonboardingconfigmodel_delete``
   * - ``admin/onboarding/noonboardingconfigmodel/<path:object_id>/history/``
     - ``history_view``
     - ``onboarding_noonboardingconfigmodel_history``
   * - ``admin/onboarding/noonboardingconfigmodel/add/``
     - ``add_view``
     - ``onboarding_noonboardingconfigmodel_add``
   * - ``admin/onboarding/onboardingconfigmodel/``
     - ``changelist_view``
     - ``onboarding_onboardingconfigmodel_changelist``
   * - ``admin/onboarding/onboardingconfigmodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/onboarding/onboardingconfigmodel/<path:object_id>/change/``
     - ``change_view``
     - ``onboarding_onboardingconfigmodel_change``
   * - ``admin/onboarding/onboardingconfigmodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``onboarding_onboardingconfigmodel_delete``
   * - ``admin/onboarding/onboardingconfigmodel/<path:object_id>/history/``
     - ``history_view``
     - ``onboarding_onboardingconfigmodel_history``
   * - ``admin/onboarding/onboardingconfigmodel/add/``
     - ``add_view``
     - ``onboarding_onboardingconfigmodel_add``
   * - ``admin/password_change/``
     - ``password_change``
     - ``password_change``
   * - ``admin/password_change/done/``
     - ``password_change_done``
     - ``password_change_done``
   * - ``admin/pki/camodel/``
     - ``changelist_view``
     - ``pki_camodel_changelist``
   * - ``admin/pki/camodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/camodel/<path:object_id>/change/``
     - ``change_view``
     - ``pki_camodel_change``
   * - ``admin/pki/camodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_camodel_delete``
   * - ``admin/pki/camodel/<path:object_id>/history/``
     - ``history_view``
     - ``pki_camodel_history``
   * - ``admin/pki/camodel/add/``
     - ``add_view``
     - ``pki_camodel_add``
   * - ``admin/pki/certificatechainordermodel/``
     - ``changelist_view``
     - ``pki_certificatechainordermodel_changelist``
   * - ``admin/pki/certificatechainordermodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/certificatechainordermodel/<path:object_id>/change/``
     - ``change_view``
     - ``pki_certificatechainordermodel_change``
   * - ``admin/pki/certificatechainordermodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_certificatechainordermodel_delete``
   * - ``admin/pki/certificatechainordermodel/<path:object_id>/history/``
     - ``history_view``
     - ``pki_certificatechainordermodel_history``
   * - ``admin/pki/certificatechainordermodel/add/``
     - ``add_view``
     - ``pki_certificatechainordermodel_add``
   * - ``admin/pki/certificatemodel/``
     - ``changelist_view``
     - ``pki_certificatemodel_changelist``
   * - ``admin/pki/certificatemodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/certificatemodel/<path:object_id>/change/``
     - ``change_view``
     - ``pki_certificatemodel_change``
   * - ``admin/pki/certificatemodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_certificatemodel_delete``
   * - ``admin/pki/certificatemodel/<path:object_id>/history/``
     - ``history_view``
     - ``pki_certificatemodel_history``
   * - ``admin/pki/certificatemodel/add/``
     - ``add_view``
     - ``pki_certificatemodel_add``
   * - ``admin/pki/credentialmodel/``
     - ``changelist_view``
     - ``pki_credentialmodel_changelist``
   * - ``admin/pki/credentialmodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/credentialmodel/<path:object_id>/change/``
     - ``change_view``
     - ``pki_credentialmodel_change``
   * - ``admin/pki/credentialmodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_credentialmodel_delete``
   * - ``admin/pki/credentialmodel/<path:object_id>/history/``
     - ``history_view``
     - ``pki_credentialmodel_history``
   * - ``admin/pki/credentialmodel/add/``
     - ``add_view``
     - ``pki_credentialmodel_add``
   * - ``admin/pki/devidregistration/``
     - ``changelist_view``
     - ``pki_devidregistration_changelist``
   * - ``admin/pki/devidregistration/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/devidregistration/<path:object_id>/change/``
     - ``change_view``
     - ``pki_devidregistration_change``
   * - ``admin/pki/devidregistration/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_devidregistration_delete``
   * - ``admin/pki/devidregistration/<path:object_id>/history/``
     - ``history_view``
     - ``pki_devidregistration_history``
   * - ``admin/pki/devidregistration/add/``
     - ``add_view``
     - ``pki_devidregistration_add``
   * - ``admin/pki/issuedcredentialmodel/``
     - ``changelist_view``
     - ``pki_issuedcredentialmodel_changelist``
   * - ``admin/pki/issuedcredentialmodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/issuedcredentialmodel/<path:object_id>/change/``
     - ``change_view``
     - ``pki_issuedcredentialmodel_change``
   * - ``admin/pki/issuedcredentialmodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_issuedcredentialmodel_delete``
   * - ``admin/pki/issuedcredentialmodel/<path:object_id>/history/``
     - ``history_view``
     - ``pki_issuedcredentialmodel_history``
   * - ``admin/pki/issuedcredentialmodel/add/``
     - ``add_view``
     - ``pki_issuedcredentialmodel_add``
   * - ``admin/pki/remoteissuedcredentialmodel/``
     - ``changelist_view``
     - ``pki_remoteissuedcredentialmodel_changelist``
   * - ``admin/pki/remoteissuedcredentialmodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/pki/remoteissuedcredentialmodel/<path:object_id>/change/``
     - ``change_view``
     - ``pki_remoteissuedcredentialmodel_change``
   * - ``admin/pki/remoteissuedcredentialmodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``pki_remoteissuedcredentialmodel_delete``
   * - ``admin/pki/remoteissuedcredentialmodel/<path:object_id>/history/``
     - ``history_view``
     - ``pki_remoteissuedcredentialmodel_history``
   * - ``admin/pki/remoteissuedcredentialmodel/add/``
     - ``add_view``
     - ``pki_remoteissuedcredentialmodel_add``
   * - ``admin/r/<path:content_type_id>/<path:object_id>/``
     - ``shortcut``
     - ``view_on_site``
   * - ``admin/signer/signedmessagemodel/``
     - ``changelist_view``
     - ``signer_signedmessagemodel_changelist``
   * - ``admin/signer/signedmessagemodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/signer/signedmessagemodel/<path:object_id>/change/``
     - ``change_view``
     - ``signer_signedmessagemodel_change``
   * - ``admin/signer/signedmessagemodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``signer_signedmessagemodel_delete``
   * - ``admin/signer/signedmessagemodel/<path:object_id>/history/``
     - ``history_view``
     - ``signer_signedmessagemodel_history``
   * - ``admin/signer/signedmessagemodel/add/``
     - ``add_view``
     - ``signer_signedmessagemodel_add``
   * - ``admin/signer/signermodel/``
     - ``changelist_view``
     - ``signer_signermodel_changelist``
   * - ``admin/signer/signermodel/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/signer/signermodel/<path:object_id>/change/``
     - ``change_view``
     - ``signer_signermodel_change``
   * - ``admin/signer/signermodel/<path:object_id>/delete/``
     - ``delete_view``
     - ``signer_signermodel_delete``
   * - ``admin/signer/signermodel/<path:object_id>/history/``
     - ``history_view``
     - ``signer_signermodel_history``
   * - ``admin/signer/signermodel/add/``
     - ``add_view``
     - ``signer_signermodel_add``
   * - ``admin/workflows2/workflow2approval/``
     - ``changelist_view``
     - ``workflows2_workflow2approval_changelist``
   * - ``admin/workflows2/workflow2approval/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2approval/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2approval_change``
   * - ``admin/workflows2/workflow2approval/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2approval_delete``
   * - ``admin/workflows2/workflow2approval/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2approval_history``
   * - ``admin/workflows2/workflow2approval/add/``
     - ``add_view``
     - ``workflows2_workflow2approval_add``
   * - ``admin/workflows2/workflow2definition/``
     - ``changelist_view``
     - ``workflows2_workflow2definition_changelist``
   * - ``admin/workflows2/workflow2definition/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2definition/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2definition_change``
   * - ``admin/workflows2/workflow2definition/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2definition_delete``
   * - ``admin/workflows2/workflow2definition/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2definition_history``
   * - ``admin/workflows2/workflow2definition/add/``
     - ``add_view``
     - ``workflows2_workflow2definition_add``
   * - ``admin/workflows2/workflow2definitionuistate/``
     - ``changelist_view``
     - ``workflows2_workflow2definitionuistate_changelist``
   * - ``admin/workflows2/workflow2definitionuistate/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2definitionuistate/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2definitionuistate_change``
   * - ``admin/workflows2/workflow2definitionuistate/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2definitionuistate_delete``
   * - ``admin/workflows2/workflow2definitionuistate/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2definitionuistate_history``
   * - ``admin/workflows2/workflow2definitionuistate/add/``
     - ``add_view``
     - ``workflows2_workflow2definitionuistate_add``
   * - ``admin/workflows2/workflow2instance/``
     - ``changelist_view``
     - ``workflows2_workflow2instance_changelist``
   * - ``admin/workflows2/workflow2instance/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2instance/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2instance_change``
   * - ``admin/workflows2/workflow2instance/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2instance_delete``
   * - ``admin/workflows2/workflow2instance/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2instance_history``
   * - ``admin/workflows2/workflow2instance/add/``
     - ``add_view``
     - ``workflows2_workflow2instance_add``
   * - ``admin/workflows2/workflow2job/``
     - ``changelist_view``
     - ``workflows2_workflow2job_changelist``
   * - ``admin/workflows2/workflow2job/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2job/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2job_change``
   * - ``admin/workflows2/workflow2job/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2job_delete``
   * - ``admin/workflows2/workflow2job/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2job_history``
   * - ``admin/workflows2/workflow2job/add/``
     - ``add_view``
     - ``workflows2_workflow2job_add``
   * - ``admin/workflows2/workflow2run/``
     - ``changelist_view``
     - ``workflows2_workflow2run_changelist``
   * - ``admin/workflows2/workflow2run/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2run/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2run_change``
   * - ``admin/workflows2/workflow2run/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2run_delete``
   * - ``admin/workflows2/workflow2run/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2run_history``
   * - ``admin/workflows2/workflow2run/add/``
     - ``add_view``
     - ``workflows2_workflow2run_add``
   * - ``admin/workflows2/workflow2steprun/``
     - ``changelist_view``
     - ``workflows2_workflow2steprun_changelist``
   * - ``admin/workflows2/workflow2steprun/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2steprun/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2steprun_change``
   * - ``admin/workflows2/workflow2steprun/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2steprun_delete``
   * - ``admin/workflows2/workflow2steprun/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2steprun_history``
   * - ``admin/workflows2/workflow2steprun/add/``
     - ``add_view``
     - ``workflows2_workflow2steprun_add``
   * - ``admin/workflows2/workflow2workerheartbeat/``
     - ``changelist_view``
     - ``workflows2_workflow2workerheartbeat_changelist``
   * - ``admin/workflows2/workflow2workerheartbeat/<path:object_id>/``
     - ``view``
     - ``-``
   * - ``admin/workflows2/workflow2workerheartbeat/<path:object_id>/change/``
     - ``change_view``
     - ``workflows2_workflow2workerheartbeat_change``
   * - ``admin/workflows2/workflow2workerheartbeat/<path:object_id>/delete/``
     - ``delete_view``
     - ``workflows2_workflow2workerheartbeat_delete``
   * - ``admin/workflows2/workflow2workerheartbeat/<path:object_id>/history/``
     - ``history_view``
     - ``workflows2_workflow2workerheartbeat_history``
   * - ``admin/workflows2/workflow2workerheartbeat/add/``
     - ``add_view``
     - ``workflows2_workflow2workerheartbeat_add``
   * - ``i18n/setlang/``
     - ``set_language``
     - ``set_language``
   * - ``jsi18n/``
     - ``view``
     - ``javascript-catalog``


Drf Spectacular
^^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``redoc/``
     - ``view``
     - ``redoc``
   * - ``schema/``
     - ``view``
     - ``schema``
   * - ``swagger/``
     - ``view``
     - ``swagger-ui``


Est
^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``.well-known/est/<str:domain>/<str:cert_profile>/csrattrs/``
     - ``view``
     - ``csrattrs``
   * - ``.well-known/est/<str:domain>/<str:cert_profile>/csrattrs/``
     - ``view``
     - ``csrattrs``
   * - ``.well-known/est/^(?P<cert_profile>~[^/]+)/simpleenroll/?$``
     - ``view``
     - ``simple-enrollment-post-nodomain``
   * - ``.well-known/est/^(?P<cert_profile>~[^/]+)/simplereenroll/?$``
     - ``view``
     - ``simple-reenrollment-post-nodomain``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/cacerts/$``
     - ``view``
     - ``ca-certs-post``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/simpleenroll/?$``
     - ``view``
     - ``simple-enrollment-post``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/simplereenroll/?$``
     - ``view``
     - ``simple-reenrollment-post``
   * - ``.well-known/est/^simpleenroll/?$``
     - ``view``
     - ``simple-enrollment-default``
   * - ``.well-known/est/^simplereenroll/?$``
     - ``view``
     - ``simple-reenrollment-default``


Home
^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``home/``
     - ``view``
     - ``index``
   * - ``home/dashboard/``
     - ``view``
     - ``dashboard``
   * - ``home/dashboard_data/``
     - ``view``
     - ``dashboard_data``
   * - ``home/simplified/``
     - ``view``
     - ``simplified_overview``
   * - ``home/simplified/enable-crl-cycle/<int:pk>/``
     - ``view``
     - ``simplified_enable_crl_cycle``


Management
^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/^backups/$``
     - ``BackupViewSet``
     - ``backup-list``
   * - ``api/^backups/(?P<pk>[^/.]+)/$``
     - ``BackupViewSet``
     - ``backup-detail``
   * - ``api/^backups/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``BackupViewSet``
     - ``backup-detail``
   * - ``api/^backups\.(?P<format>[a-z0-9]+)/?$``
     - ``BackupViewSet``
     - ``backup-list``
   * - ``api/^logging/delete/(?P<file_name>[^/]+)/$``
     - ``LoggingViewSet``
     - ``logging-delete``
   * - ``api/^logging/delete/(?P<file_name>[^/]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``LoggingViewSet``
     - ``logging-delete``
   * - ``api/^logging/download/(?P<file_name>[^/]+)/$``
     - ``LoggingViewSet``
     - ``logging-download``
   * - ``api/^logging/download/(?P<file_name>[^/]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``LoggingViewSet``
     - ``logging-download``
   * - ``api/^logging/list_files/$``
     - ``LoggingViewSet``
     - ``logging-list-files``
   * - ``api/^logging/list_files\.(?P<format>[a-z0-9]+)/?$``
     - ``LoggingViewSet``
     - ``logging-list-files``
   * - ``api/^tls/$``
     - ``TlsViewSet``
     - ``tls-list``
   * - ``api/^tls/(?P<pk>[^/.]+)/$``
     - ``TlsViewSet``
     - ``tls-detail``
   * - ``api/^tls/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``TlsViewSet``
     - ``tls-detail``
   * - ``api/^tls\.(?P<format>[a-z0-9]+)/?$``
     - ``TlsViewSet``
     - ``tls-list``
   * - ``management/``
     - ``view``
     - ``index``
   * - ``management/^logging/files/details/(?P<filename>trustpoint\.log(?:\.\d{1,5})?)/?$``
     - ``view``
     - ``logging-files-details``
   * - ``management/^logging/files/download/(?P<archive_format>tar\.gz\|zip)(?P<filenames>(?:/trustpoint\.log(\.\d{1,5})?)+)/?$``
     - ``view``
     - ``logging-files-download-multiple``
   * - ``management/^logging/files/download/(?P<filename>trustpoint\.log(?:\.\d{1,5})?)/?$``
     - ``view``
     - ``logging-files-download``
   * - ``management/^tls/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``tls-delete_confirm``
   * - ``management/audit-log/``
     - ``view``
     - ``audit-log``
   * - ``management/backend-configuration/``
     - ``view``
     - ``backend_configuration``
   * - ``management/backups/``
     - ``view``
     - ``backups``
   * - ``management/backups/delete-multiple/``
     - ``view``
     - ``backup-delete-multiple``
   * - ``management/backups/download-multiple/<str:archive_format>/``
     - ``view``
     - ``backup-download-multiple``
   * - ``management/backups/download/<str:filename>/``
     - ``view``
     - ``backup-download``
   * - ``management/docs/``
     - ``view``
     - ``local_docs``
   * - ``management/docs/<path:path>``
     - ``view``
     - ``local_docs_path``
   * - ``management/docs/build/trigger/``
     - ``view``
     - ``trigger_build_docs``
   * - ``management/help/``
     - ``view``
     - ``help``
   * - ``management/logging/files/``
     - ``view``
     - ``logging-files``
   * - ``management/loglevel/change``
     - ``view``
     - ``change-loglevel``
   * - ``management/notifications/``
     - ``view``
     - ``notifications``
   * - ``management/notifications/<int:pk>/``
     - ``view``
     - ``notification_details``
   * - ``management/notifications/<int:pk>/delete/``
     - ``view``
     - ``notification_delete``
   * - ``management/notifications/<int:pk>/mark-as-solved/``
     - ``view``
     - ``mark_as_solved``
   * - ``management/notifications/<int:pk>/toggle-read/``
     - ``view``
     - ``notification_toggle_read``
   * - ``management/notifications/refresh/``
     - ``view``
     - ``refresh_notifications``
   * - ``management/settings/``
     - ``view``
     - ``settings``
   * - ``management/settings/internationalization/``
     - ``view``
     - ``settings-internationalization``
   * - ``management/settings/logging/``
     - ``view``
     - ``settings-logging``
   * - ``management/settings/metrics/``
     - ``view``
     - ``settings-metrics``
   * - ``management/settings/notifications/``
     - ``view``
     - ``settings-notifications``
   * - ``management/settings/security/``
     - ``view``
     - ``settings-security``
   * - ``management/settings/ui/``
     - ``view``
     - ``settings-ui``
   * - ``management/tls/``
     - ``view``
     - ``tls``
   * - ``management/tls/activate/<int:pk>``
     - ``view``
     - ``activate-tls``
   * - ``management/tls/add/file-import/pkcs12``
     - ``view``
     - ``tls-add-file_import-pkcs12``
   * - ``management/tls/add/file-import/separate-files``
     - ``view``
     - ``tls-add-file_import-separate_files``
   * - ``management/tls/add/generate-tls``
     - ``view``
     - ``tls-generate``
   * - ``management/tls/add/method-select/``
     - ``view``
     - ``tls-add-method_select``


Pki
^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/^cert-profiles/$``
     - ``CertProfileViewSet``
     - ``cert-profiles-list``
   * - ``api/^cert-profiles/(?P<pk>[^/.]+)/$``
     - ``CertProfileViewSet``
     - ``cert-profiles-detail``
   * - ``api/^cert-profiles/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``CertProfileViewSet``
     - ``cert-profiles-detail``
   * - ``api/^cert-profiles\.(?P<format>[a-z0-9]+)/?$``
     - ``CertProfileViewSet``
     - ``cert-profiles-list``
   * - ``api/^certificates/$``
     - ``CertificateViewSet``
     - ``certificate-list``
   * - ``api/^certificates/(?P<pk>[^/.]+)/$``
     - ``CertificateViewSet``
     - ``certificate-detail``
   * - ``api/^certificates/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``CertificateViewSet``
     - ``certificate-detail``
   * - ``api/^certificates\.(?P<format>[a-z0-9]+)/?$``
     - ``CertificateViewSet``
     - ``certificate-list``
   * - ``api/^devid-registrations/$``
     - ``DevIdRegistrationViewSet``
     - ``devid-registration-list``
   * - ``api/^devid-registrations/(?P<pk>[^/.]+)/$``
     - ``DevIdRegistrationViewSet``
     - ``devid-registration-detail``
   * - ``api/^devid-registrations/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``DevIdRegistrationViewSet``
     - ``devid-registration-detail``
   * - ``api/^devid-registrations\.(?P<format>[a-z0-9]+)/?$``
     - ``DevIdRegistrationViewSet``
     - ``devid-registration-list``
   * - ``api/^devownerid/$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-list``
   * - ``api/^devownerid/(?P<pk>[^/.]+)/$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-detail``
   * - ``api/^devownerid/(?P<pk>[^/.]+)/request/devownerid/$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-request-devownerid``
   * - ``api/^devownerid/(?P<pk>[^/.]+)/request/devownerid\.(?P<format>[a-z0-9]+)/?$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-request-devownerid``
   * - ``api/^devownerid/(?P<pk>[^/.]+)/request/domain_credential/$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-request-domain-credential``
   * - ``api/^devownerid/(?P<pk>[^/.]+)/request/domain_credential\.(?P<format>[a-z0-9]+)/?$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-request-domain-credential``
   * - ``api/^devownerid/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-detail``
   * - ``api/^devownerid\.(?P<format>[a-z0-9]+)/?$``
     - ``DevOwnerIdViewSet``
     - ``devownerid-list``
   * - ``api/^domains/$``
     - ``DomainViewSet``
     - ``domain-list``
   * - ``api/^domains/(?P<pk>[^/.]+)/$``
     - ``DomainViewSet``
     - ``domain-detail``
   * - ``api/^domains/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``DomainViewSet``
     - ``domain-detail``
   * - ``api/^domains\.(?P<format>[a-z0-9]+)/?$``
     - ``DomainViewSet``
     - ``domain-list``
   * - ``api/^issuing-cas/$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-list``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-detail``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/crl/$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/crl\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/generate-crl/$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-generate-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/generate-crl\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-generate-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-detail``
   * - ``api/^issuing-cas\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaViewSet``
     - ``issuing-ca-list``
   * - ``api/^truststores/$``
     - ``TruststoreViewSet``
     - ``truststore-list``
   * - ``api/^truststores/(?P<pk>[^/.]+)/$``
     - ``TruststoreViewSet``
     - ``truststore-detail``
   * - ``api/^truststores/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``TruststoreViewSet``
     - ``truststore-detail``
   * - ``api/^truststores\.(?P<format>[a-z0-9]+)/?$``
     - ``TruststoreViewSet``
     - ``truststore-list``
   * - ``crl/<int:pk>/``
     - ``view``
     - ``crl-download``
   * - ``pki/^cas/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``cas-delete_confirm``
   * - ``pki/^cert-profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``cert_profiles-delete_confirm``
   * - ``pki/^certificates/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/(?P<file_name>[^/]+)/?$``
     - ``view``
     - ``certificate-file-download-file-name``
   * - ``pki/^certificates/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$``
     - ``view``
     - ``certificate-file-download``
   * - ``pki/^certificates/download/(?P<pk>[0-9]+)/?$``
     - ``view``
     - ``certificate-download``
   * - ``pki/^certificates/download/(?P<pks>([0-9]+/)+[0-9]+)/?$``
     - ``view``
     - ``certificates-download``
   * - ``pki/^certificates/download/multiple/(?P<file_format>[a-zA-Z0-9_]+)/(?P<archive_format>[a-zA-Z0-9_]+)/(?P<pks>([0-9]+/)+[0-9]+)/?$``
     - ``view``
     - ``certificates-file-download``
   * - ``pki/^crls/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``crls-delete_confirm``
   * - ``pki/^crls/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$``
     - ``view``
     - ``crl-file-download``
   * - ``pki/^crls/download/(?P<pk>[0-9]+)/?$``
     - ``view``
     - ``crl-download``
   * - ``pki/^devid-registration/method_select/(?P<pk>\d+)?/?$``
     - ``view``
     - ``devid_registration-method_select``
   * - ``pki/^domains/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``domains-delete_confirm``
   * - ``pki/^issuing-cas/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``issuing_cas-delete_confirm``
   * - ``pki/^owner-credentials/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``owner_credentials-delete_confirm``
   * - ``pki/^truststores/add/(?P<pk>\d+)?/?$``
     - ``view``
     - ``truststores-add-with-pk``
   * - ``pki/^truststores/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``truststore-delete_confirm``
   * - ``pki/^truststores/download/(?P<file_format>[a-zA-Z0-9_]+)/(?P<pk>[0-9]+)/?$``
     - ``view``
     - ``truststore-file-download``
   * - ``pki/^truststores/download/(?P<pk>[0-9]+)/?$``
     - ``view``
     - ``truststore-download``
   * - ``pki/^truststores/download/(?P<pks>([0-9]+/)+[0-9]+)/?$``
     - ``view``
     - ``truststores-download``
   * - ``pki/^truststores/download/multiple/(?P<file_format>[a-zA-Z0-9_]+)/(?P<archive_format>[a-zA-Z0-9_]+)/(?P<pks>([0-9]+/)+[0-9]+)/?$``
     - ``view``
     - ``truststores-file-download``
   * - ``pki/cas/``
     - ``view``
     - ``cas``
   * - ``pki/cert-profiles/``
     - ``view``
     - ``cert_profiles``
   * - ``pki/cert-profiles/add/``
     - ``view``
     - ``cert_profiles-add``
   * - ``pki/cert-profiles/config/<int:pk>/``
     - ``view``
     - ``cert_profiles-details``
   * - ``pki/cert-profiles/issuance/<int:pk>/``
     - ``view``
     - ``cert_profiles-issuance``
   * - ``pki/certificates/``
     - ``view``
     - ``certificates``
   * - ``pki/certificates/details/<int:pk>/``
     - ``view``
     - ``certificate-detail``
   * - ``pki/certificates/download/issuing-ca/<int:pk>/``
     - ``view``
     - ``certificate-issuing-ca-download``
   * - ``pki/crls/``
     - ``view``
     - ``crls``
   * - ``pki/crls/details/<int:pk>/``
     - ``view``
     - ``crl-detail``
   * - ``pki/crls/import/``
     - ``view``
     - ``crl-import``
   * - ``pki/devid-registration/create/(?P<pk>\d+)?/?$``
     - ``view``
     - ``devid_registration_create``
   * - ``pki/devid-registration/create/<int:pk>/<int:truststore_id>/``
     - ``view``
     - ``devid_registration_create-with_truststore_id``
   * - ``pki/devid-registration/delete/<int:pk>/``
     - ``view``
     - ``devid_registration_delete``
   * - ``pki/domains/``
     - ``view``
     - ``domains``
   * - ``pki/domains/add/``
     - ``view``
     - ``domains-add``
   * - ``pki/domains/config/<int:pk>/``
     - ``view``
     - ``domains-config``
   * - ``pki/domains/config/<int:pk>/help/cmp-idevid-registration/``
     - ``view``
     - ``help_onboarding_cmp_idevid_registration``
   * - ``pki/domains/config/<int:pk>/help/est-idevid-registration/``
     - ``view``
     - ``help_onboarding_est_idevid_registration``
   * - ``pki/domains/config/<int:pk>/help/onboarding-method-select-idevid/``
     - ``view``
     - ``help_onboarding_method_select_idevid``
   * - ``pki/domains/detail/<int:pk>/``
     - ``view``
     - ``domains-detail``
   * - ``pki/domains/issued-certificates/<int:pk>/``
     - ``view``
     - ``domain-issued_certificates``
   * - ``pki/issuing-cas/``
     - ``view``
     - ``issuing_cas``
   * - ``pki/issuing-cas/add/cmp-ra/``
     - ``view``
     - ``issuing_cas-add-cmp-ra``
   * - ``pki/issuing-cas/add/est-ra/``
     - ``view``
     - ``issuing_cas-add-est-ra``
   * - ``pki/issuing-cas/add/file-import/pkcs12``
     - ``view``
     - ``issuing_cas-add-file_import-pkcs12``
   * - ``pki/issuing-cas/add/file-import/separate-files``
     - ``view``
     - ``issuing_cas-add-file_import-separate_files``
   * - ``pki/issuing-cas/add/method-select/``
     - ``view``
     - ``issuing_cas-add-method_select``
   * - ``pki/issuing-cas/add/request-cmp/``
     - ``view``
     - ``issuing_cas-add-request-cmp``
   * - ``pki/issuing-cas/add/request-est/``
     - ``view``
     - ``issuing_cas-add-request-est``
   * - ``pki/issuing-cas/config/<int:pk>/``
     - ``view``
     - ``issuing_cas-config``
   * - ``pki/issuing-cas/config/<int:pk>/help/crl-download/``
     - ``view``
     - ``help_issuing_cas_crl_download``
   * - ``pki/issuing-cas/crl-gen/<int:pk>/``
     - ``view``
     - ``issuing_cas-crl-gen``
   * - ``pki/issuing-cas/define-cert-content-cmp/<int:pk>/``
     - ``view``
     - ``issuing_cas-define-cert-content-cmp``
   * - ``pki/issuing-cas/define-cert-content-est/<int:pk>/``
     - ``view``
     - ``issuing_cas-define-cert-content-est``
   * - ``pki/issuing-cas/detail/<int:pk>/``
     - ``view``
     - ``issuing_cas-detail``
   * - ``pki/issuing-cas/issued-certificates/<int:pk>``
     - ``view``
     - ``issuing_ca-issued_certificates``
   * - ``pki/issuing-cas/request-cert-cmp/<int:pk>/``
     - ``view``
     - ``issuing_cas-request-cert-cmp``
   * - ``pki/issuing-cas/request-cert-est/<int:pk>/``
     - ``view``
     - ``issuing_cas-request-cert-est``
   * - ``pki/issuing-cas/truststore-association/<int:pk>/``
     - ``view``
     - ``issuing_cas-truststore-association``
   * - ``pki/keyless-cas/config/<int:pk>/``
     - ``view``
     - ``keyless_cas-config``
   * - ``pki/owner-credentials/``
     - ``view``
     - ``owner_credentials``
   * - ``pki/owner-credentials/<int:owner_pk>/issued-credential/<int:pk>/delete/``
     - ``view``
     - ``owner_credentials-issued-credential-delete``
   * - ``pki/owner-credentials/add/``
     - ``view``
     - ``owner_credentials-add``
   * - ``pki/owner-credentials/add/est/``
     - ``view``
     - ``owner_credentials-add-est``
   * - ``pki/owner-credentials/add/est/no-onboarding/``
     - ``view``
     - ``owner_credentials-add-est-no-onboarding``
   * - ``pki/owner-credentials/add/est/onboarding/``
     - ``view``
     - ``owner_credentials-add-est-onboarding``
   * - ``pki/owner-credentials/add/file-import/``
     - ``view``
     - ``owner_credentials-add-file_import``
   * - ``pki/owner-credentials/clm/<int:pk>/``
     - ``view``
     - ``owner_credentials-clm``
   * - ``pki/owner-credentials/define-cert-content-domain-credential-est/<int:pk>/``
     - ``view``
     - ``owner_credentials-define-cert-content-domain-credential-est``
   * - ``pki/owner-credentials/define-cert-content-est/<int:pk>/``
     - ``view``
     - ``owner_credentials-define-cert-content-est``
   * - ``pki/owner-credentials/details/<int:pk>/``
     - ``view``
     - ``owner_credentials-details``
   * - ``pki/owner-credentials/request-cert-est/<int:pk>/``
     - ``view``
     - ``owner_credentials-request-cert-est``
   * - ``pki/owner-credentials/request-domain-credential-est/<int:pk>/``
     - ``view``
     - ``owner_credentials-request-domain-credential-est``
   * - ``pki/owner-credentials/truststore-association/<int:pk>/``
     - ``view``
     - ``owner_credentials-truststore-association``
   * - ``pki/trustpoint/download/tls-server/``
     - ``view``
     - ``trustpoint-tls-server-download``
   * - ``pki/truststores/``
     - ``view``
     - ``truststores``
   * - ``pki/truststores/add/``
     - ``view``
     - ``truststores-add``
   * - ``pki/truststores/add/<int:pk>/``
     - ``view``
     - ``truststores-add-with-pk``
   * - ``pki/truststores/add/from-device/``
     - ``view``
     - ``truststores-add-from-device``
   * - ``pki/truststores/details/<int:pk>/``
     - ``view``
     - ``truststore-detail``


Rest Framework
^^^^^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/``
     - ``view``
     - ``api-root``
   * - ``api/``
     - ``view``
     - ``api-root``
   * - ``api/``
     - ``view``
     - ``api-root``
   * - ``api/``
     - ``view``
     - ``api-root``
   * - ``api/``
     - ``view``
     - ``api-root``
   * - ``api/<drf_format_suffix:format>``
     - ``view``
     - ``api-root``
   * - ``api/<drf_format_suffix:format>``
     - ``view``
     - ``api-root``
   * - ``api/<drf_format_suffix:format>``
     - ``view``
     - ``api-root``
   * - ``api/<drf_format_suffix:format>``
     - ``view``
     - ``api-root``
   * - ``api/<drf_format_suffix:format>``
     - ``view``
     - ``api-root``


Rest Pki
^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/rest-pki/enroll/``
     - ``view``
     - ``rest-pki-enroll``
   * - ``rest/^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/enroll/?$``
     - ``view``
     - ``enroll``
   * - ``rest/^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/reenroll/?$``
     - ``view``
     - ``reenroll``
   * - ``rest/^(?P<domain>[^/]+)/enroll/?$``
     - ``view``
     - ``enroll-default-profile``


Signer
^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/^signed-messages/$``
     - ``SignedMessageViewSet``
     - ``signed-message-list``
   * - ``api/^signed-messages/(?P<pk>[^/.]+)/$``
     - ``SignedMessageViewSet``
     - ``signed-message-detail``
   * - ``api/^signed-messages/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``SignedMessageViewSet``
     - ``signed-message-detail``
   * - ``api/^signed-messages\.(?P<format>[a-z0-9]+)/?$``
     - ``SignedMessageViewSet``
     - ``signed-message-list``
   * - ``api/^signers/$``
     - ``SignerViewSet``
     - ``signer-list``
   * - ``api/^signers/(?P<pk>[^/.]+)/$``
     - ``SignerViewSet``
     - ``signer-detail``
   * - ``api/^signers/(?P<pk>[^/.]+)/certificate/$``
     - ``SignerViewSet``
     - ``signer-get-certificate``
   * - ``api/^signers/(?P<pk>[^/.]+)/certificate\.(?P<format>[a-z0-9]+)/?$``
     - ``SignerViewSet``
     - ``signer-get-certificate``
   * - ``api/^signers/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``SignerViewSet``
     - ``signer-detail``
   * - ``api/^signers/sign/$``
     - ``SignerViewSet``
     - ``signer-sign-hash``
   * - ``api/^signers/sign\.(?P<format>[a-z0-9]+)/?$``
     - ``SignerViewSet``
     - ``signer-sign-hash``
   * - ``api/^signers\.(?P<format>[a-z0-9]+)/?$``
     - ``SignerViewSet``
     - ``signer-list``
   * - ``signer/``
     - ``view``
     - ``signer_list``
   * - ``signer/^delete/(?P<pks>([0-9]+/)*[0-9]*)/?$``
     - ``view``
     - ``signer-delete_confirm``
   * - ``signer/add/file-import/file-type-select/``
     - ``view``
     - ``signer-add-file_import-file_type_select``
   * - ``signer/add/file-import/pkcs12``
     - ``view``
     - ``signer-add-file_import-pkcs12``
   * - ``signer/add/file-import/separate-files``
     - ``view``
     - ``signer-add-file_import-separate_files``
   * - ``signer/add/generate/``
     - ``view``
     - ``signer-add-generate``
   * - ``signer/add/method-select/``
     - ``view``
     - ``signer-add-method_select``
   * - ``signer/config/<int:pk>/``
     - ``view``
     - ``signer-config``
   * - ``signer/sign-hash/``
     - ``view``
     - ``sign_hash``
   * - ``signer/sign-hash/success/``
     - ``view``
     - ``sign_hash_success``
   * - ``signer/signed-messages/<int:pk>/``
     - ``view``
     - ``signer-signed_messages``


Trustpoint
^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ````
     - ``view``
     - ``-``
   * - ``api/token/``
     - ``view``
     - ``token_obtain_pair``
   * - ``api/token/refresh/``
     - ``view``
     - ``token_refresh``
   * - ``prometheus/metrics``
     - ``prometheus_metrics_view``
     - ``prometheus-metrics``


Users
^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``users/login/``
     - ``view``
     - ``login``
   * - ``users/logout/``
     - ``view``
     - ``logout``


Workflows2
^^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/^workflow2-definitions/$``
     - ``Workflow2DefinitionViewSet``
     - ``workflow2-definition-list``
   * - ``api/^workflow2-definitions/(?P<pk>[^/.]+)/$``
     - ``Workflow2DefinitionViewSet``
     - ``workflow2-definition-detail``
   * - ``api/^workflow2-definitions/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``Workflow2DefinitionViewSet``
     - ``workflow2-definition-detail``
   * - ``api/^workflow2-definitions\.(?P<format>[a-z0-9]+)/?$``
     - ``Workflow2DefinitionViewSet``
     - ``workflow2-definition-list``
   * - ``workflows2/api/context-catalog/``
     - ``view``
     - ``context_catalog``
   * - ``workflows2/api/definitions/<uuid:pk>/graph/``
     - ``view``
     - ``api_definition_graph``
   * - ``workflows2/api/graph-from-yaml/``
     - ``view``
     - ``api_graph_from_yaml``
   * - ``workflows2/api/triggers/``
     - ``view``
     - ``api_triggers``
   * - ``workflows2/approvals/``
     - ``view``
     - ``approvals-list``
   * - ``workflows2/approvals/<uuid:approval_id>/``
     - ``view``
     - ``approvals-detail``
   * - ``workflows2/approvals/<uuid:approval_id>/resolve/``
     - ``view``
     - ``approvals-resolve``
   * - ``workflows2/definitions/``
     - ``view``
     - ``definitions_list``
   * - ``workflows2/definitions/<uuid:pk>/``
     - ``view``
     - ``definitions_edit``
   * - ``workflows2/definitions/new/``
     - ``view``
     - ``definitions_new``
   * - ``workflows2/instances/<uuid:instance_id>/``
     - ``view``
     - ``instances-detail``
   * - ``workflows2/instances/<uuid:instance_id>/cancel/``
     - ``view``
     - ``instances-cancel``
   * - ``workflows2/instances/<uuid:instance_id>/resume/``
     - ``view``
     - ``instances-resume``
   * - ``workflows2/instances/<uuid:instance_id>/run-inline/``
     - ``view``
     - ``instances-run-inline``
   * - ``workflows2/instances/<uuid:instance_id>/stop/``
     - ``view``
     - ``instances-stop``
   * - ``workflows2/runs/``
     - ``view``
     - ``runs-list``
   * - ``workflows2/runs/<uuid:run_id>/``
     - ``view``
     - ``runs-detail``
   * - ``workflows2/runs/<uuid:run_id>/cancel/``
     - ``view``
     - ``runs-cancel``
   * - ``workflows2/runs/<uuid:run_id>/release-idempotency/``
     - ``view``
     - ``runs-release-idempotency``
   * - ``workflows2/runs/<uuid:run_id>/run-inline/``
     - ``view``
     - ``runs-run-inline``
   * - ``workflows2/waiting/``
     - ``view``
     - ``waiting-list``

