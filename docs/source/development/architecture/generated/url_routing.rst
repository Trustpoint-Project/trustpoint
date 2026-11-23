URL Routing Map
===============

This document maps URL patterns to their corresponding views across the Trustpoint application.

URL Patterns by App
-------------------


Agents
^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``agents/<int:agent_id>/assigned-profiles/``
     - ``view``
     - ``assigned-profiles-list``
   * - ``agents/<int:agent_id>/assigned-profiles/<int:pk>/edit/``
     - ``view``
     - ``assigned-profiles-edit``
   * - ``agents/<int:agent_id>/assigned-profiles/<int:pk>/force-update/``
     - ``view``
     - ``assigned-profiles-force-update``
   * - ``agents/<int:agent_id>/assigned-profiles/create/``
     - ``view``
     - ``assigned-profiles-create``
   * - ``agents/^(?P<agent_id>[0-9]+)/assigned-profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``assigned-profiles-delete_confirm``
   * - ``agents/^profiles/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``profiles-delete_confirm``
   * - ``agents/profiles/``
     - ``view``
     - ``profiles``
   * - ``agents/profiles/<int:pk>/``
     - ``view``
     - ``profiles-config``
   * - ``agents/profiles/create/``
     - ``view``
     - ``profiles-create``
   * - ``api/agents/jobs/``
     - ``view``
     - ``agent-jobs``
   * - ``api/agents/jobs/result/``
     - ``view``
     - ``agent-jobs-result``


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
   * - ``api/^devices/(?P<pk>[^/.]+)/change-secret/$``
     - ``DeviceViewSet``
     - ``device-change-secret``
   * - ``api/^devices/(?P<pk>[^/.]+)/change-secret\.(?P<format>[a-z0-9]+)/?$``
     - ``DeviceViewSet``
     - ``device-change-secret``
   * - ``api/^devices/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``DeviceViewSet``
     - ``device-detail``
   * - ``api/^devices\.(?P<format>[a-z0-9]+)/?$``
     - ``DeviceViewSet``
     - ``device-list``
   * - ``devices/``
     - ``view``
     - ``devices``
   * - ``devices/^agents/delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``agents_device_delete``
   * - ``devices/^agents/revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``agents_device_revoke``
   * - ``devices/^delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_delete``
   * - ``devices/^opc-ua-gds-push/delete-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_delete``
   * - ``devices/^opc-ua-gds-push/revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``opc_ua_gds_push_device_revoke``
   * - ``devices/^revoke-device(?:/(?P<pks>[0-9]+(?:/[0-9]+)*))?/?$``
     - ``view``
     - ``devices_device_revoke``
   * - ``devices/^zero-touch-credentials/delete(?:/(?P<pks>([0-9]+/)*[0-9]*))?/?$``
     - ``view``
     - ``zero_touch_credentials-delete_confirm``
   * - ``devices/agents/``
     - ``view``
     - ``agents``
   * - ``devices/agents/create/1-to-1/``
     - ``view``
     - ``agents_create_one_to_one``
   * - ``devices/browser/``
     - ``view``
     - ``browser_login``
   * - ``devices/browser/credential-download/<int:pk>/``
     - ``view``
     - ``browser_domain_credential_download``
   * - ``devices/certificate-lifecycle-management/<int:pk>/``
     - ``view``
     - ``devices_certificate_lifecycle_management``
   * - ``devices/certificate-lifecycle-management/<int:pk>/agent/setup-profile/``
     - ``view``
     - ``devices_agent_setup_profile_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/agent/setup-profile/download-script/``
     - ``view``
     - ``devices_agent_setup_script_download``
   * - ``devices/certificate-lifecycle-management/<int:pk>/agent/setup-profile/download/``
     - ``view``
     - ``devices_agent_setup_profile_download``
   * - ``devices/certificate-lifecycle-management/<int:pk>/change-secret/``
     - ``view``
     - ``devices_change_secret``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/``
     - ``view``
     - ``devices_no_onboarding_clm_issue_application_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cmp-shared-secret/``
     - ``view``
     - ``devices_no_onboarding_cmp_shared_secret_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/cmp-webui/``
     - ``view``
     - ``devices_no_onboarding_cmp_webui_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/est-username-password/``
     - ``view``
     - ``devices_no_onboarding_est_username_password_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/est-webui/``
     - ``view``
     - ``devices_no_onboarding_est_webui_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/profile/<int:profile_id>/``
     - ``view``
     - ``devices_certificate_lifecycle_management_issue_profile_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/profile/<int:profile_id>/choose-method/``
     - ``view``
     - ``devices_certificate_lifecycle_management_choose_issuance_method``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/profile/<int:profile_id>/csr/``
     - ``view``
     - ``devices_certificate_lifecycle_management_issue_csr_credential``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/manual/select-certificate-profile``
     - ``view``
     - ``devices_no_onboarding_select_certificate_profile``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/rest-username-password/``
     - ``view``
     - ``devices_no_onboarding_rest_username_password_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/scep/``
     - ``view``
     - ``devices_no_onboarding_scep_help``
   * - ``devices/certificate-lifecycle-management/<int:pk>/no-onboarding/issue-application-credential/scep/download-config/``
     - ``view``
     - ``scep_config_download``
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
   * - ``devices/certificate-lifecycle-management/<int:pk>/revoke/cmp/``
     - ``view``
     - ``devices_device_revoke_cmp_help``
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
   * - ``devices/opc-ua-gds-push/<int:pk>/domain-credential-renewal-settings/``
     - ``view``
     - ``devices_domain_credential_renewal_settings``
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
   * - ``devices/revoke/<int:pk>/``
     - ``view``
     - ``devices_credential_revoke``
   * - ``devices/trust-bundle-download/<int:pk>/``
     - ``view``
     - ``trust_bundle_download``
   * - ``devices/zero-touch-credentials/``
     - ``view``
     - ``zero_touch_credentials``
   * - ``devices/zero-touch-credentials/<int:pk>/delete/``
     - ``view``
     - ``zero_touch_credentials-delete``
   * - ``devices/zero-touch-credentials/add/``
     - ``view``
     - ``zero_touch_credentials-add``
   * - ``devices/zero-touch-credentials/add/external-csr/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-external-csr``
   * - ``devices/zero-touch-credentials/add/external-csr/<int:pk>/content/``
     - ``view``
     - ``zero_touch_credentials-external-csr-content``
   * - ``devices/zero-touch-credentials/add/external-csr/key/``
     - ``view``
     - ``zero_touch_credentials-external-csr-key``
   * - ``devices/zero-touch-credentials/add/file-import/``
     - ``view``
     - ``zero_touch_credentials-add-file_import``
   * - ``devices/zero-touch-credentials/add/file-import/pkcs12/``
     - ``view``
     - ``zero_touch_credentials-add-file_import-pkcs12``
   * - ``devices/zero-touch-credentials/add/management-ca/``
     - ``view``
     - ``zero_touch_credentials-add-management-ca``
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
   * - ``devices/zero-touch-credentials/define-cert-content-management-ca/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-define-cert-content-management-ca``
   * - ``devices/zero-touch-credentials/details/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-details``
   * - ``devices/zero-touch-credentials/onboarding-setup/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-onboarding-setup``
   * - ``devices/zero-touch-credentials/request-cert-management-ca/<int:pk>/``
     - ``view``
     - ``zero_touch_credentials-request-cert-management-ca``


Discovery
^^^^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``discovery/``
     - ``view``
     - ``device_list``
   * - ``discovery/clear/``
     - ``view``
     - ``clear_devices``
   * - ``discovery/device/<int:device_id>/``
     - ``view``
     - ``device_detail``
   * - ``discovery/export-csv/``
     - ``view``
     - ``export_csv``
   * - ``discovery/port-config/``
     - ``view``
     - ``port_config``
   * - ``discovery/port/add/``
     - ``view``
     - ``add_port``
   * - ``discovery/port/delete/<int:port_id>/``
     - ``view``
     - ``delete_port``
   * - ``discovery/start-scan/``
     - ``view``
     - ``start_scan``
   * - ``discovery/stop-scan/``
     - ``view``
     - ``stop_scan``


Django
^^^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
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
   * - ``.well-known/est/^(?P<cert_profile>~[^/]+)/csrattrs/?$``
     - ``view``
     - ``csrattrs-profile``
   * - ``.well-known/est/^(?P<cert_profile>~[^/]+)/simpleenroll/?$``
     - ``view``
     - ``simple-enrollment-post-nodomain``
   * - ``.well-known/est/^(?P<cert_profile>~[^/]+)/simplereenroll/?$``
     - ``view``
     - ``simple-reenrollment-post-nodomain``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/cacerts/?$``
     - ``view``
     - ``ca-certs-post``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/csrattrs/?$``
     - ``view``
     - ``csrattrs``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/simpleenroll/?$``
     - ``view``
     - ``simple-enrollment-post``
   * - ``.well-known/est/^(?P<domain>[^/]+)(?:/(?P<cert_profile>[^/]+))?/simplereenroll/?$``
     - ``view``
     - ``simple-reenrollment-post``
   * - ``.well-known/est/^cacerts/?$``
     - ``view``
     - ``ca-certs-default``
   * - ``.well-known/est/^csrattrs/?$``
     - ``view``
     - ``csrattrs-default``
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
   * - ``home/dashboard/analytics/``
     - ``view``
     - ``dashboard_analytics``
   * - ``home/dashboard/notifications/``
     - ``view``
     - ``dashboard_notifications``
   * - ``home/dashboard/overview/``
     - ``view``
     - ``dashboard_overview``
   * - ``home/dashboard/security/``
     - ``view``
     - ``dashboard_security``
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
   * - ``api/^audit-logs/$``
     - ``AuditLogViewSet``
     - ``audit-log-list``
   * - ``api/^audit-logs\.(?P<format>[a-z0-9]+)/?$``
     - ``AuditLogViewSet``
     - ``audit-log-list``
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
   * - ``api/^capabilities/$``
     - ``CapabilitiesViewSet``
     - ``capabilities-list``
   * - ``api/^capabilities\.(?P<format>[a-z0-9]+)/?$``
     - ``CapabilitiesViewSet``
     - ``capabilities-list``
   * - ``api/^health/$``
     - ``HealthViewSet``
     - ``health-list``
   * - ``api/^health\.(?P<format>[a-z0-9]+)/?$``
     - ``HealthViewSet``
     - ``health-list``
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
   * - ``api/^roles/$``
     - ``RoleViewSet``
     - ``roles-list``
   * - ``api/^roles/(?P<pk>[^/.]+)/$``
     - ``RoleViewSet``
     - ``roles-detail``
   * - ``api/^roles/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``RoleViewSet``
     - ``roles-detail``
   * - ``api/^roles/available-permissions/$``
     - ``RoleViewSet``
     - ``roles-available-permissions``
   * - ``api/^roles/available-permissions\.(?P<format>[a-z0-9]+)/?$``
     - ``RoleViewSet``
     - ``roles-available-permissions``
   * - ``api/^roles\.(?P<format>[a-z0-9]+)/?$``
     - ``RoleViewSet``
     - ``roles-list``
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
   * - ``api/^users/$``
     - ``UserViewSet``
     - ``users-list``
   * - ``api/^users/(?P<pk>[^/.]+)/$``
     - ``UserViewSet``
     - ``users-detail``
   * - ``api/^users/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``UserViewSet``
     - ``users-detail``
   * - ``api/^users\.(?P<format>[a-z0-9]+)/?$``
     - ``UserViewSet``
     - ``users-list``
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
   * - ``management/audit-log/export/``
     - ``view``
     - ``audit-log-export``
   * - ``management/audit-log/export/download/``
     - ``view``
     - ``audit-log-export-download``
   * - ``management/audit-log/signing/``
     - ``view``
     - ``audit-log-signing``
   * - ``management/audit-log/verify/``
     - ``view``
     - ``audit-log-verify``
   * - ``management/backend-configuration/``
     - ``view``
     - ``backend_configuration``
   * - ``management/backend-configuration/pkcs11-assets/<str:asset>/download/``
     - ``view``
     - ``backend_configuration_pkcs11_asset_download``
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
   * - ``management/organization/``
     - ``view``
     - ``organization``
   * - ``management/organization/<int:pk>/delete/``
     - ``view``
     - ``delete_organization``
   * - ``management/organization/<int:pk>/edit/``
     - ``view``
     - ``edit_organization``
   * - ``management/organization/add/``
     - ``view``
     - ``add_organization``
   * - ``management/role_management/``
     - ``view``
     - ``role_management``
   * - ``management/role_management/<int:pk>/delete/``
     - ``view``
     - ``delete_role``
   * - ``management/role_management/<int:pk>/edit/``
     - ``view``
     - ``edit_role``
   * - ``management/role_management/add/``
     - ``view``
     - ``add_role``
   * - ``management/service-accounts/``
     - ``view``
     - ``service_account_list``
   * - ``management/service-accounts/<int:pk>/``
     - ``view``
     - ``service_account_detail``
   * - ``management/service-accounts/<int:pk>/delete/``
     - ``view``
     - ``delete_service_account``
   * - ``management/service-accounts/<int:pk>/generate-credential/``
     - ``generate_credential_view``
     - ``generate_credential``
   * - ``management/service-accounts/create/``
     - ``view``
     - ``service_account_create``
   * - ``management/service-accounts/created/``
     - ``service_account_created_view``
     - ``service_account_created``
   * - ``management/service-accounts/credentials/<int:pk>/revoke/``
     - ``revoke_credential_view``
     - ``revoke_credential``
   * - ``management/settings/``
     - ``view``
     - ``settings``
   * - ``management/settings/account-security/``
     - ``view``
     - ``settings-account-security``
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
   * - ``management/tls/``
     - ``view``
     - ``tls``
   * - ``management/tls/activate/<int:pk>``
     - ``view``
     - ``activate-tls``
   * - ``management/tls/add/external-csr/<int:pk>/``
     - ``view``
     - ``tls-external-csr``
   * - ``management/tls/add/external-csr/<int:pk>/content/``
     - ``view``
     - ``tls-external-csr-content``
   * - ``management/tls/add/external-csr/<int:pk>/truststore/``
     - ``view``
     - ``tls-external-csr-truststore``
   * - ``management/tls/add/external-csr/key/``
     - ``view``
     - ``tls-external-csr-key``
   * - ``management/tls/add/file-import/pkcs12``
     - ``view``
     - ``tls-add-file_import-pkcs12``
   * - ``management/tls/add/file-import/separate-files``
     - ``view``
     - ``tls-add-file_import-separate_files``
   * - ``management/tls/add/generate-tls``
     - ``view``
     - ``tls-generate``
   * - ``management/tls/add/local/<int:pk>/content/``
     - ``view``
     - ``tls-local-content``
   * - ``management/tls/add/local/<int:pk>/request/``
     - ``view``
     - ``tls-local-request``
   * - ``management/tls/add/local/key/``
     - ``view``
     - ``tls-local-key``
   * - ``management/tls/add/method-select/``
     - ``view``
     - ``tls-add-method_select``
   * - ``management/tls/add/request-cmp/``
     - ``view``
     - ``tls-request-cmp``
   * - ``management/tls/add/request-est/``
     - ``view``
     - ``tls-request-est``
   * - ``management/tls/cmp-truststore-association/<int:pk>/``
     - ``view``
     - ``tls-cmp-truststore-association``
   * - ``management/tls/define-cert-content-cmp/<int:pk>/``
     - ``view``
     - ``tls-define-cert-content-cmp``
   * - ``management/tls/define-cert-content-est/<int:pk>/``
     - ``view``
     - ``tls-define-cert-content-est``
   * - ``management/tls/request-cert-cmp/<int:pk>/``
     - ``view``
     - ``tls-request-cert-cmp``
   * - ``management/tls/request-cert-est/<int:pk>/``
     - ``view``
     - ``tls-request-cert-est``
   * - ``management/tls/truststore-association/<int:pk>/``
     - ``view``
     - ``tls-truststore-association``
   * - ``management/traceability-credentials/``
     - ``view``
     - ``traceability_credentials``
   * - ``management/traceability-credentials/<int:pk>/``
     - ``view``
     - ``traceability_credential_detail``
   * - ``management/traceability-credentials/<int:pk>/edit/``
     - ``view``
     - ``traceability_credential_edit``
   * - ``management/traceability-credentials/<int:pk>/retire/``
     - ``view``
     - ``traceability_credential_retire``
   * - ``management/traceability-credentials/<int:pk>/rotate/``
     - ``view``
     - ``traceability_credential_rotate``
   * - ``management/traceability-credentials/create/``
     - ``view``
     - ``traceability_credential_create``
   * - ``management/traceability-credentials/create/<str:method>/``
     - ``view``
     - ``traceability_credential_configure``
   * - ``management/user-authentication/``
     - ``view``
     - ``user_authentication``
   * - ``management/user-authentication/certificate/``
     - ``view``
     - ``certificate_authentication``
   * - ``management/user-authentication/password/``
     - ``view``
     - ``password_policy``
   * - ``management/user-authentication/password/list/download/``
     - ``view``
     - ``password_policy_list_download``
   * - ``management/user-management/``
     - ``view``
     - ``user_management``
   * - ``management/user-management/<int:pk>/change_password/``
     - ``view``
     - ``change_password``
   * - ``management/user-management/<int:pk>/change_role/``
     - ``view``
     - ``change_role``
   * - ``management/user-management/<int:pk>/configure/``
     - ``view``
     - ``configure_user``
   * - ``management/user-management/<int:pk>/delete/``
     - ``view``
     - ``delete_user``
   * - ``management/user-management/<int:pk>/details/``
     - ``view``
     - ``user_details``
   * - ``management/user-management/<int:pk>/reset_otp/``
     - ``view``
     - ``reset_otp``
   * - ``management/user-management/add_user/``
     - ``view``
     - ``add_user``


Pki
^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``api/^ca-rollovers/$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-list``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-detail``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/cancel/$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-cancel``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/cancel\.(?P<format>[a-z0-9]+)/?$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-cancel``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/complete/$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-complete``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/complete\.(?P<format>[a-z0-9]+)/?$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-complete``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/start/$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-start``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/start\.(?P<format>[a-z0-9]+)/?$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-start``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/transition/$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-transition``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)/transition\.(?P<format>[a-z0-9]+)/?$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-transition``
   * - ``api/^ca-rollovers/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-detail``
   * - ``api/^ca-rollovers\.(?P<format>[a-z0-9]+)/?$``
     - ``CaRolloverViewSet``
     - ``ca-rollover-list``
   * - ``api/^cas/$``
     - ``CaViewSet``
     - ``ca-list``
   * - ``api/^cas/(?P<pk>[^/.]+)/$``
     - ``CaViewSet``
     - ``ca-detail``
   * - ``api/^cas/(?P<pk>[^/.]+)/certificate/$``
     - ``CaViewSet``
     - ``ca-certificate``
   * - ``api/^cas/(?P<pk>[^/.]+)/certificate\.(?P<format>[a-z0-9]+)/?$``
     - ``CaViewSet``
     - ``ca-certificate``
   * - ``api/^cas/(?P<pk>[^/.]+)/issued-certificates/$``
     - ``CaViewSet``
     - ``ca-issued-certificates``
   * - ``api/^cas/(?P<pk>[^/.]+)/issued-certificates\.(?P<format>[a-z0-9]+)/?$``
     - ``CaViewSet``
     - ``ca-issued-certificates``
   * - ``api/^cas/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``CaViewSet``
     - ``ca-detail``
   * - ``api/^cas\.(?P<format>[a-z0-9]+)/?$``
     - ``CaViewSet``
     - ``ca-list``
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
   * - ``api/^certificates/(?P<pk>[^/.]+)/download/$``
     - ``CertificateViewSet``
     - ``certificate-download``
   * - ``api/^certificates/(?P<pk>[^/.]+)/download\.(?P<format>[a-z0-9]+)/?$``
     - ``CertificateViewSet``
     - ``certificate-download``
   * - ``api/^certificates/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``CertificateViewSet``
     - ``certificate-detail``
   * - ``api/^certificates/download/$``
     - ``CertificateViewSet``
     - ``certificate-download-multiple``
   * - ``api/^certificates/download\.(?P<format>[a-z0-9]+)/?$``
     - ``CertificateViewSet``
     - ``certificate-download-multiple``
   * - ``api/^certificates\.(?P<format>[a-z0-9]+)/?$``
     - ``CertificateViewSet``
     - ``certificate-list``
   * - ``api/^crls/$``
     - ``CrlViewSet``
     - ``crl-api-list``
   * - ``api/^crls/(?P<pk>[^/.]+)/$``
     - ``CrlViewSet``
     - ``crl-api-detail``
   * - ``api/^crls/(?P<pk>[^/.]+)/download/$``
     - ``CrlViewSet``
     - ``crl-api-download``
   * - ``api/^crls/(?P<pk>[^/.]+)/download\.(?P<format>[a-z0-9]+)/?$``
     - ``CrlViewSet``
     - ``crl-api-download``
   * - ``api/^crls/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``CrlViewSet``
     - ``crl-api-detail``
   * - ``api/^crls\.(?P<format>[a-z0-9]+)/?$``
     - ``CrlViewSet``
     - ``crl-api-list``
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
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-list``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-detail``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/certificate/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-certificate``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/certificate\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-certificate``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/crl-settings/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-crl-settings``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/crl-settings\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-crl-settings``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/crl/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/crl\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/csr/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-csr``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/csr\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-csr``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/enroll/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-enroll``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/enroll\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-enroll``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/generate-crl/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-generate-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/generate-crl\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-generate-crl``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/import-certificate/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-import-certificate``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/import-certificate\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-import-certificate``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/issued-certificates/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-issued-certificates``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/issued-certificates\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-issued-certificates``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/truststore/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-truststore``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)/truststore\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-truststore``
   * - ``api/^issuing-cas/(?P<pk>[^/.]+)\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-detail``
   * - ``api/^issuing-cas/configure-cmp/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-configure-cmp``
   * - ``api/^issuing-cas/configure-cmp\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-configure-cmp``
   * - ``api/^issuing-cas/configure-est/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-configure-est``
   * - ``api/^issuing-cas/configure-est\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-configure-est``
   * - ``api/^issuing-cas/configure-external-csr/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-configure-external-csr``
   * - ``api/^issuing-cas/configure-external-csr\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-configure-external-csr``
   * - ``api/^issuing-cas/generate/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-generate``
   * - ``api/^issuing-cas/generate\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-generate``
   * - ``api/^issuing-cas/import-pkcs12/$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-import-pkcs12``
   * - ``api/^issuing-cas/import-pkcs12\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
     - ``issuing-ca-import-pkcs12``
   * - ``api/^issuing-cas\.(?P<format>[a-z0-9]+)/?$``
     - ``IssuingCaManagementViewSet``
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
   * - ``crl/<int:pk>.crl``
     - ``view``
     - ``crl-download-file``
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
   * - ``pki/issuing-cas/add/``
     - ``view``
     - ``issuing_cas-add-role_select``
   * - ``pki/issuing-cas/add/autogen/``
     - ``view``
     - ``issuing_cas-add-autogen``
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
   * - ``pki/issuing-cas/add/request-external-csr/``
     - ``view``
     - ``issuing_cas-add-request-external-csr``
   * - ``pki/issuing-cas/add/self-signed-management-ca/``
     - ``view``
     - ``issuing_cas-add-self_signed_management_ca``
   * - ``pki/issuing-cas/cmp-truststore-association/<int:pk>/``
     - ``view``
     - ``issuing_cas-cmp-truststore-association``
   * - ``pki/issuing-cas/config/<int:pk>/``
     - ``view``
     - ``issuing_cas-config``
   * - ``pki/issuing-cas/config/<int:pk>/help/crl-download/``
     - ``view``
     - ``help_issuing_cas_crl_download``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/<int:rollover_pk>/cancel/``
     - ``view``
     - ``issuing_cas-rollover-cancel``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/<int:rollover_pk>/complete/``
     - ``view``
     - ``issuing_cas-rollover-complete``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/<int:rollover_pk>/start/``
     - ``view``
     - ``issuing_cas-rollover-start``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/<int:rollover_pk>/transition/``
     - ``view``
     - ``issuing_cas-rollover-transition``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/file-method-select/``
     - ``view``
     - ``issuing_cas-rollover-file-method-select``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/import-pkcs12/``
     - ``view``
     - ``issuing_cas-rollover-import-pkcs12``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/import-separate-files/``
     - ``view``
     - ``issuing_cas-rollover-import-separate-files``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/method-select/``
     - ``view``
     - ``issuing_cas-rollover-method-select``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/plan/``
     - ``view``
     - ``issuing_cas-rollover-plan``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/request-cmp/``
     - ``view``
     - ``issuing_cas-rollover-request-cmp``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/request-est/``
     - ``view``
     - ``issuing_cas-rollover-request-est``
   * - ``pki/issuing-cas/config/<int:pk>/rollover/request-method-select/``
     - ``view``
     - ``issuing_cas-rollover-request-method-select``
   * - ``pki/issuing-cas/crl-gen/<int:pk>/``
     - ``view``
     - ``issuing_cas-crl-gen``
   * - ``pki/issuing-cas/define-cert-content-cmp/<int:pk>/``
     - ``view``
     - ``issuing_cas-define-cert-content-cmp``
   * - ``pki/issuing-cas/define-cert-content-csr/<int:pk>/``
     - ``view``
     - ``issuing_cas-define-cert-content-csr``
   * - ``pki/issuing-cas/define-cert-content-est/<int:pk>/``
     - ``view``
     - ``issuing_cas-define-cert-content-est``
   * - ``pki/issuing-cas/detail/<int:pk>/``
     - ``view``
     - ``issuing_cas-detail``
   * - ``pki/issuing-cas/est-truststore-association/<int:pk>/``
     - ``view``
     - ``issuing_cas-est-truststore-association``
   * - ``pki/issuing-cas/external-csr/<int:pk>/``
     - ``view``
     - ``issuing_cas-external-csr``
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
   * - ``pki/owner-credentials/<int:pk>/delete/``
     - ``view``
     - ``owner_credentials-delete``
   * - ``pki/owner-credentials/add/``
     - ``view``
     - ``owner_credentials-add``
   * - ``pki/owner-credentials/add/file-import/``
     - ``view``
     - ``owner_credentials-add-file_import``
   * - ``pki/owner-credentials/add/management-ca/``
     - ``view``
     - ``owner_credentials-add-management-ca``
   * - ``pki/owner-credentials/clm/<int:pk>/``
     - ``view``
     - ``owner_credentials-clm``
   * - ``pki/owner-credentials/define-cert-content-management-ca/<int:pk>/``
     - ``view``
     - ``owner_credentials-define-cert-content-management-ca``
   * - ``pki/owner-credentials/details/<int:pk>/``
     - ``view``
     - ``owner_credentials-details``
   * - ``pki/owner-credentials/request-cert-management-ca/<int:pk>/``
     - ``view``
     - ``owner_credentials-request-cert-management-ca``
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
   * - ``api/rest-pki/revoke/``
     - ``view``
     - ``rest-pki-revoke``
   * - ``rest/^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/enroll/?$``
     - ``view``
     - ``enroll``
   * - ``rest/^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/reenroll/?$``
     - ``view``
     - ``reenroll``
   * - ``rest/^(?P<domain>[^/]+)/enroll/?$``
     - ``view``
     - ``enroll-default-profile``


Scep
^^^^

.. list-table::
   :header-rows: 1
   :widths: 40 30 30

   * - URL Pattern
     - View
     - Name
   * - ``.well-known/scep/^(?P<domain>[^/]+)/$``
     - ``view``
     - ``endpoint``
   * - ``.well-known/scep/^(?P<domain>[^/]+)/(?P<cert_profile>[^/]+)/$``
     - ``view``
     - ``endpoint-profile``


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
   * - ``/``
     - ``view``
     - ``-``
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
   * - ``api/token/``
     - ``view``
     - ``token_obtain_pair``
   * - ``users/login/``
     - ``view``
     - ``login``
   * - ``users/login/otp/``
     - ``view``
     - ``otp``
   * - ``users/logout/``
     - ``view``
     - ``logout``
   * - ``users/password-change-required/``
     - ``view``
     - ``password-change-required``
   * - ``users/profile/``
     - ``view``
     - ``profile``
   * - ``users/profile/<int:pk>/``
     - ``view``
     - ``user-profile``
   * - ``users/profile/<int:pk>/delete/``
     - ``view``
     - ``user-profile-delete``
   * - ``users/profile/<int:pk>/password/``
     - ``view``
     - ``user-profile-password``
   * - ``users/profile/certificate-authentication/``
     - ``view``
     - ``profile_certificate_authentication``
   * - ``users/profile/certificate-authentication/<int:pk>/<str:action>/``
     - ``view``
     - ``profile_client_certificate_action``
   * - ``users/profile/delete/``
     - ``view``
     - ``profile_delete``
   * - ``users/profile/details/``
     - ``view``
     - ``profile_details``
   * - ``users/profile/password/``
     - ``view``
     - ``profile_password``
   * - ``users/profile/reset-otp/``
     - ``view``
     - ``profile_reset_otp``
   * - ``users/profile/role/``
     - ``view``
     - ``profile_role``


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

