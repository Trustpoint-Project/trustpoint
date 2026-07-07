============================
Trustpoint Management API
============================

Overview
--------
The Trustpoint Management API provides a comprehensive set of REST endpoints for administering and configuring Trustpoint. This API enables secure, programmatic access to manage users, domains, certificate authorities, devices, workflows, and system settings.

.. note::

   This is the **Management API** (``/api/``). For certificate enrollment operations, see the :doc:`REST PKI API <rest>`, :doc:`EST API <est>`, or :doc:`CMP API <cmp>`.

Key Features
------------

The Management API allows you to:

- **Certificate Authority Management**: Create and manage CAs, domains, and certificate profiles
- **Device Management**: Register, onboard, and monitor devices
- **User Management**: Manage user accounts, roles, and permissions
- **Workflow Management**: Configure and monitor approval workflows
- **System Administration**: Configure security settings, view logs, and monitor system health

Base URL
--------

All Management API endpoints are accessible under::

    https://<trustpoint-host>/api/

Authentication
--------------

The Management API uses JWT (JSON Web Tokens) for authentication.

Obtaining a Token
^^^^^^^^^^^^^^^^^

Request an access token using your username and password::

    POST /api/token/
    Content-Type: application/json

    {
        "username": "your-username",
        "password": "your-password"
    }

Response::

    {
        "access": "<access-token>",
        "refresh": "<refresh-token>"
    }

Using the Token
^^^^^^^^^^^^^^^

Include the access token in the Authorization header::

    Authorization: Bearer <access-token>

Example::

    curl -X GET https://trustpoint.example.com/api/domains/ \
      -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGc..."

Refreshing the Token
^^^^^^^^^^^^^^^^^^^^

Access tokens expire after a period. Use the refresh token to obtain a new access token::

    POST /api/token/refresh/
    Content-Type: application/json

    {
        "refresh": "<refresh-token>"
    }

Interactive Documentation
--------------------------

Trustpoint provides interactive API documentation using Swagger UI and ReDoc:

- **Swagger UI**: ``https://<trustpoint-host>/api/schema/swagger-ui/``

The interactive documentation allows you to:

- Browse all available endpoints
- View request/response schemas
- Test API calls directly in the browser
- Generate code samples

Definition
----------

.. openapi:: ../../_static/trustpoint-openapi-swagger.yaml
   :group:
   :examples: