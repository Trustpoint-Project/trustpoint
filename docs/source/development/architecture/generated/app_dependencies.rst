Application Dependencies
========================

This diagram shows the dependency relationships between Trustpoint applications.

.. image:: app_dependencies.svg
   :alt: Application Dependency Graph
   :align: center

**Legend:**

- **Arrows** indicate import dependencies (A → B means A imports from B)
- **Clusters** group related applications
- **Colors** indicate different application modules

Key Applications
----------------

- **help_pages**: Help pages application configuration.
- **shared**: Shared application configuration.
- **appsecrets**: Django app config for Trustpoint application secrets.
- **setup_wizard**: Configuration for the setup wizard app.
- **users**: App configuration for the users app.
- **home**: Configures the Home application, including its name and other settings for Django.
- **devices**: Devices application configuration.
- **onboarding**: Configuration class for the Onboarding app.
- **pki**: Configuration for the PKI app.
- **cmp**: Cmp Configuration.
- **est**: EST Configuration.
- **rest_pki**: REST PKI Configuration.
- **signer**: Configuration for the Signer app.
- **aoki**: Configuration for the AOKI app.
- **crypto**: Register the crypto app for Django.
- **management**: Management application configuration.
- **workflows2**: Register Workflow 2 startup hooks.
- **behave_django**: Class representing a Django application and its configuration.
