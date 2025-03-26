.. _trustpoint_dev_env_setup:

========================================
Trustpoint Development environment setup
========================================

Installation
------------

| Trustpoint uses the Python Django framework.
| We are using `uv <https://docs.astral.sh/uv/>`__ to manage different python versions and
  dependencies.

Please note that the current version is in **development status** and
still subject to **major changes**. Our aim is to make an operational
version of the software available quickly in order to receive as much
feedback as possible from users.

Install uv
^^^^^^^^^^

| You should use uv to create a virtual environment and to manage
  the dependencies (instead of pip directly).
| Check out the official documentation for the `installer
  <https://docs.astral.sh/uv/getting-started/installation>`__

In simple cases, installing uv is as straightforward as:

.. code:: shell

   pip install uv

Install dependencies with uv
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you have an existing virtual environment, e.g. through using python3
-m venv, exit the virtual environment (that is make sure you are not in
the environment). You can usually exit it with:

.. code:: shell

   deactivate

Then, remove any virtual environment you may have set up, e.g. .venv/
directory.

Finally, install everything through uv:

.. code:: shell

   cd /path/to/trustpoint/
   uv sync

Activating the environment
^^^^^^^^^^^^^^^^^^^^^^^^^^

It is generally not required to manually activate the virtual environment,
just start your command with ``uv run`` instead of ``python``.
However, if you do want to activate the environment manually, you can do so using

.. code:: shell

   source .venv/bin/activate

Usage
-----

Setting up the DB and SuperUser
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The development server supports a PostgreSQL database by default.
The connection settings can be configured in the ``settings.py`` file.
If the configured database is not available, the server will fall back
to a built-in SQLite database.

Next, it is required to migrate (creating the required tables) and create a superuser.
The superuser credentials ``admin``/``testing321`` can later be used to access the
Trustpoint user interface at localhost:8000.

.. code:: bash

   cd trustpoint
   uv run manage.py reset_db

Finally, compile the translation strings for non-English language support:

.. code:: bash

   uv run manage.py compilemsg -l de

Running the development server
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   uv run manage.py runserver

You can then access the GUI through localhost:8000.

Alternatively, use the following command to run a development HTTPS
server (self-signed certificate).

.. code:: bash

   python manage.py runserver_plus 0.0.0.0:443 --cert-file ../tests/data/x509/https_server.crt --key-file ../tests/data/x509/https_server.pem

Use the following command to automatically generate a self-signed TLS
server certificate for your current IP addresses:

.. code:: bash

   python manage.py create_tls_certs

Logging in
^^^^^^^^^^

Browsing to any page should redirect you to the login page. The login
page can be accessed directly via /users/login/.

Use the username and password which you previously provided through the
**createsuperuser** command.

Management commands for testing and development purposes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   uv run manage.py reset_db

Clears the database and restores Trustpoint to the initial state.

.. code:: bash

   uv run manage.py add_domains_and_devices

Populates the database with an example CA, domain and device instances.

.. code:: bash

   uv run manage.py makemsg -l de
   uv run manage.py makemsg -l de -d djangojs

Makes the translation (.po) files from translatable strings. gettext
must be installed on your system.

.. code:: bash

   uv run manage.py compilemsg -l de

Compiles the translation files (.po) to binary (.mo) files actually used
by Django.

Building auto documentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: bash

   cd ../docs
   sphinx-apidoc -f -e -o ./source ../trustpoint /*/migrations/*
   make html

Adding dependencies to the project
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Dependencies generally required for the project can be added using the
following:

.. code:: shell

   uv add <name-of-package>

Dependencies that are only required in development, use the following to
add in within the dev section:

.. code:: shell

   uv add <name-of-package> --dev

Testing & CI
------------

Using the ruff linter and formatter
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For linting everything in the current directory use:

.. code:: shell

   uv run ruff check . --output-format=concise

For active formatting everything in the current directory use:

.. code:: shell

   uv run ruff format .

For type checking, we use :term:`mypy`:

.. code:: shell

   uv run mypy .

Running pytest unit tests
^^^^^^^^^^^^^^^^^^^^^^^^^

Trustpoint uses pytest to run self-contained tests, either unit tests
or integration tests that do not involve a request-response cycle:

.. code:: shell

   uv run pytest

Running BDD tests with behave
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Trustpoint uses behave to run BDD tests. The tests are located in the
``features/`` directory:

.. code:: shell

   uv run behave
