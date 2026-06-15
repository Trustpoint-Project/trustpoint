.. _quickstart-setup-guide:

Quickstart Setup Guide
======================

This guide covers setting up Trustpoint using Docker and Docker Compose.

Prerequisites
-------------

- **Docker** 20.10 or higher
- **Docker Compose** v2.32.4 or higher
- **Git**

Getting started with the Trustpoint Wizard script
--------------------------------------------------

The ``tp_wizard.sh`` script provides a guided CLI for setting up a Docker environment.
This requires a Linux host.

.. code-block:: bash

    git clone https://github.com/Trustpoint-Project/trustpoint.git
    cd trustpoint
    ./tp_wizard.sh

Convenience commands:

- ``./tp_wizard.sh up`` — start Trustpoint and Postgres with default testing credentials (testing only).
- ``./tp_wizard.sh up demo`` — additionally start SFTP and mailpit demo servers (testing only).
- ``./tp_wizard.sh down`` — stop and remove all containers.
- ``./tp_wizard.sh nuke`` — remove all containers and delete all stored data.

Getting started with Docker Compose
------------------------------------

The .env file
^^^^^^^^^^^^^

All deployments require a ``.env`` file in the project root.
Copy the provided template and fill in the required values:

.. code-block:: bash

    cp .env.example .env

The following variables are supported:

.. list-table::
   :widths: 30 10 60
   :header-rows: 1

   * - Variable
     - Required
     - Description
   * - ``DATABASE_USER``
     - Yes
     - PostgreSQL username. Avoid generic defaults such as ``admin``.
   * - ``DATABASE_PASSWORD``
     - Yes
     - PostgreSQL password. Generate a strong value: ``openssl rand -base64 32``
   * - ``POSTGRES_DB``
     - No
     - Database name. Defaults to ``trustpoint_db``.
   * - ``TP_URLS``
     - No
     - Comma-separated hostnames or IPs at which Trustpoint is reachable (no protocol prefix). Defaults to ``localhost``.

Minimal ``.env`` example:

.. code-block:: bash

    DATABASE_USER=trustpoint
    DATABASE_PASSWORD=correct-horse-battery-staple
    TP_URLS=trustpoint.myfactory.local,10.0.0.5

Setup (Load from Docker Hub)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Download `docker-compose.yml <https://raw.githubusercontent.com/Trustpoint-Project/trustpoint/refs/heads/main/docker-compose.yml>`_
   and `.env.example <https://raw.githubusercontent.com/Trustpoint-Project/trustpoint/refs/heads/main/.env.example>`_.

2. Create the ``.env`` file as described above.

3. Start all containers:

   .. code-block:: bash

       docker compose up -d

   .. note::

   If the specified ports are already in use, adjust the port mappings in ``docker-compose.yml``.

Setup (Build from source)
^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Clone the repository:

   .. code-block:: bash

       git clone https://github.com/Trustpoint-Project/trustpoint.git
       cd trustpoint

2. Create the ``.env`` file as described above.

3. Build the images:

   .. code-block:: bash

       docker compose build

4. Start all containers:

   .. code-block:: bash

       docker compose up -d

   .. note::

      If the specified ports are already in use, adjust the port mappings in ``docker-compose.yml``.

Getting Started with Docker
----------------------------

Setup (Load from Docker Hub)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Pull the images:

   .. code-block:: bash

       docker pull trustpointproject/trustpoint:latest
       docker pull trustpointproject/postgres:latest

2. Run the containers:

   .. code-block:: bash

       docker run -d --name postgres-<version> \
           -v postgres_data-<version>:/var/lib/postgresql \
           -p 127.0.0.1:5432:5432 \
           -e POSTGRES_USER=<db-user> \
           -e POSTGRES_PASSWORD=<db-password> \
           -e POSTGRES_DB=trustpoint_db \
           trustpointproject/postgres:latest

       docker run -d --name trustpoint-<version> \
           --link postgres-<version> \
           -p 80:80 -p 443:443 \
           -e POSTGRES_DB=trustpoint_db \
           -e DATABASE_USER=<db-user> \
           -e DATABASE_PASSWORD=<db-password> \
           -e DATABASE_HOST=postgres-<version> \
           -e DATABASE_PORT=5432 \
           trustpointproject/trustpoint:latest

   .. note::

      PostgreSQL 18+ stores data under ``/var/lib/postgresql/18/main``.
      Mount the volume at ``/var/lib/postgresql``, not ``/var/lib/postgresql/data``.

Setup (Build from source)
^^^^^^^^^^^^^^^^^^^^^^^^^^

1. Clone the repository and build the images:

   .. code-block:: bash

       git clone https://github.com/Trustpoint-Project/trustpoint.git
       cd trustpoint
       docker build -t trustpointproject/postgres:latest -f docker/db/Dockerfile .
       docker build -t trustpointproject/trustpoint:latest -f docker/trustpoint/Dockerfile .

2. Run the containers (replace ``<db-user>`` and ``<db-password>`` with strong values):

   .. code-block:: bash

       docker run -d --name postgres-<version> \
           -v postgres_data-<version>:/var/lib/postgresql \
           -p 127.0.0.1:5432:5432 \
           -e POSTGRES_USER=<db-user> \
           -e POSTGRES_PASSWORD=<db-password> \
           -e POSTGRES_DB=trustpoint_db \
           trustpointproject/postgres:latest

       docker run -d --name trustpoint-<version> \
           --link postgres-<version> \
           -p 80:80 -p 443:443 \
           -e POSTGRES_DB=trustpoint_db \
           -e DATABASE_USER=<db-user> \
           -e DATABASE_PASSWORD=<db-password> \
           -e DATABASE_HOST=postgres-<version> \
           -e DATABASE_PORT=5432 \
           trustpointproject/trustpoint:latest

Verify the Setup
----------------

Once the containers are running:

- Open ``http://localhost`` in your browser to access the Trustpoint setup wizard.
- The wizard generates a TLS certificate on first run. After that, only HTTPS connections are accepted. You may need to accept a self-signed certificate in your browser.
- Set a strong password for the admin user when prompted.

Change the Admin User Password
-------------------------------

- Go to ``https://localhost/admin``.
- Click **Users**, select the **admin** user.
- Click the "change password" link, enter a new password, and click **Save**.

Tips and Troubleshooting
-------------------------

**View logs:**

.. code-block:: bash

    docker compose logs trustpoint -f
    docker compose logs postgres -f

**Stop and remove containers and volumes:**

.. code-block:: bash

    docker compose down -v

What to Do Next
----------------

1. **Explore with test data**: Navigate to **Home > Notifications > Populate Test Data** in the Trustpoint interface.

2. **Use the Trustpoint Client**: Install the `Trustpoint Client <https://trustpoint-client.readthedocs.io>`_ on end devices for streamlined certificate issuance.

3. **Issue your first certificate**: Follow the steps in :ref:`quickstart-operation-guide`.
