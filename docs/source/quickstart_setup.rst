.. _quickstart-setup-guide:

Quickstart Setup Guide
======================

This guide provides an introduction to Trustpoint and instructions for setting up the Trustpoint using Docker and Docker Compose.

Getting Started with Docker 🐳
------------------------------

Prerequisites ✅
^^^^^^^^^^^^^^^^
Make sure you have the following installed:

1. **Docker**: Version 20.10 or higher.
2. **Git**: To clone the Trustpoint repository.

Step-by-Step Setup (Load from Dockerhub) ⬇️
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Pull the Trustpoint Docker Image**

   First, pull the Trustpoint Docker image from Docker Hub. This command will download the pre-built container image directly:

   .. code-block:: bash

        docker pull trustpoint2023/trustpoint:latest
        docker pull postgres:17

   This command pulls the latest versions of the Trustpoint and Postgres images from Docker Hub.

2. **Run the Trustpoint Container with a Custom Name and Port Mappings** 🚀

   Once the image is pulled, you can start a new container with a custom name and port mappings:

   .. code-block:: bash

       docker run -d --name trustpoint-container -p 80:80 -p 443:443 trustpoint2023/trustpoint:latest
       docker run -d --name postgres -p 5432:5432 postgres:17

   - **-d**: Runs the container in detached mode.
   - **--name trustpoint-container**: Names the Trustpoint container `trustpoint-container`.
   - **--name postgres**: Names the postgres container `postgres`.
   - **-p 80:80**: Maps the Trustpoint container's HTTP port to your local machine's port 80.
   - **-p 443:443**: Maps the Trustpoint container's HTTPS port to your local machine's port 443.
   - **-p 5432:5432**: Maps the postgres container's TCP port to your local machine's port 5432.

Step-by-Step Setup (Build container) 🔧
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Clone the Trustpoint Repository**

   First, clone the Trustpoint source code from the official repository:

   .. code-block:: bash

       git clone https://github.com/TrustPoint-Project/trustpoint.git
       cd trustpoint

   This command downloads the Trustpoint source code to your local machine and navigates into the project directory.

2. **Build the Trustpoint Docker Image**

   Use Docker to build the Trustpoint and Postgres images from the source:

   .. code-block:: bash

       docker build -t trustpoint .
       docker build -f postgre.Dockerfile -t postgres .

   - **-t trustpoint**: Tags the image with the name `trustpoint`.
   - **-t postgres**: Tags the postgres image with the name `postgres`.
   - **.**: Specifies the current directory as the build context.

3. **Run the Trustpoint Container with a Custom Name and Port Mappings** 🚀

   Start the Trustpoint container using the image you just built, with a custom name and both port mappings:

   .. code-block:: bash

       docker run -d --name trustpoint-container -p 80:80 -p 443:443 trustpoint
       docker run -d --name postgres -p 5432:5432 postgres

   - **-d**: Runs the container in detached mode.
   - **--name trustpoint-container**: Names the Trustpoint container `trustpoint-container`.
   - **--name postgres**: Names the postgres container `postgres`.
   - **-p 80:80**: Maps the Trustpoint container's HTTP port to your local machine's port 80.
   - **-p 443:443**: Maps the Trustpoint container's HTTPS port to your local machine's port 443.
   - **-p 5432:5432**: Maps the postgres container's TCP port to your local machine's port 5432.

Getting Started with Docker Compose 🐙
--------------------------------------

Prerequisites ✅
^^^^^^^^^^^^^^^^
Make sure you have the following installed:

1. **Docker Compose**: Version v2.32.4 or higher.
2. **Git**: To clone the Trustpoint repository.

Step-by-Step Setup (Load from Dockerhub) ⬇️
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Pull the Trustpoint and Postres Docker Images**

   You can pull the pre-built docker images from Docker Hub with the following command:

   .. code-block:: bash

       docker compose pull

2. **Run the Trustpoint and Postgres Containers** 🚀

   Once the images are pulled, you can start trustpoint and prostgres containers with following command:

   .. code-block:: bash

       docker compose up -d

  - **-d**: Runs the container in detached mode.

Step-by-Step Setup (Build container) 🔧
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

1. **Clone the Trustpoint Repository**

   First, clone the Trustpoint source code from the official repository:

   .. code-block:: bash

       git clone https://github.com/TrustPoint-Project/trustpoint.git
       cd trustpoint

   This command downloads the Trustpoint source code to your local machine and navigates into the project directory.

   .. note::
      The database connection between the containers uses default credentials for testing. THIS IS INSECURE.
      It is highly encouraged to change the default credentials in the `docker-compose.yml` file before building the containers.

2. **Build the Trustpoint and Postgres Docker Images**

   Use docker compose to build the Trustpoint and Postgres images from the source:

   .. code-block:: bash

       docker compose build

3. **Run the Trustpoint and Prostgres Containers** 🚀

   Start the Trustpoint and Postgres containers using the images you just built:

   .. code-block:: bash

       docker compose up -d

   - **-d**: Runs the container in detached mode.


Verify the Setup 🔍
-------------------

Once the containers are running, you can verify the setup:

- **Web Interface**: Open `http://localhost` in your browser to access the Trustpoint setup wizard.
- **TLS Connection**: As the first step of the wizard, a TLS server certificate is generated. After this, only HTTPS connections will be accepted.

.. note::
   You may need to accept a self-signed certificate in your browser to proceed.

- **Set Credentials**: Be sure to choose a strong password for the admin user during the setup wizard.

.. admonition:: 🥳 CONGRATULATIONS!
   :class: tip

   You’ve successfully set up Trustpoint! Your environment is now ready to securely manage digital identities for your industrial devices. You can start registering devices, issuing certificates, and building a trusted network.

Change the Current Admin User Password 🔑
-----------------------------------------

To secure your Trustpoint setup, it may be important to change the default admin user password:

- Go to https://localhost/admin
- Click on the **Users** section in the Django admin dashboard.
- Select the **admin** user from the list.
- Scroll down to the **password field** and click the "change password" link.
- Enter and confirm the new password.
- Click **Save** to update the password.

Tips and Troubleshooting 🧰
---------------------------

- **View Logs**: For troubleshooting, view logs with:

  .. code-block:: bash

      docker logs -f trustpoint-container
      docker logs -f postgres
      docker compose logs trustpoint -f
      docker compose logs postgres -f

- **Stop and Remove the Container**: Stop and remove the container with:

  .. code-block:: bash

      docker stop trustpoint-container postgres && docker rm trustpoint-container postgres
      docker compose down -v


What to Do Next ➡️
------------------

After setting up and Trustpoint, here are some recommended next steps to explore the full capabilities of the platform:

1. **Explore Trustpoint with test data** 🧪:
   Familiarize yourself with Trustpoint’s functionalities by running it with sample test data. To populate test data, navigate to **Home > Notifications > Populate Test Data** in the Trustpoint interface.

2. **Use the Trustpoint in conjunction with the Trustpoint Client** 💻:
   The easiest way to fully utilize Trustpoint is by pairing it with the associated Trustpoint Client, which is installed on end devices. The client enables streamlined identity management and certificate issuance. For more details, visit the `Trustpoint-Client Documentation <https://trustpoint-client.readthedocs.io>`_.

3. **Issue your first certificate for an end device** 🛡️:
   To do this, you need an Issuing CA certificate, a domain and a device that you must define in Trustpoint. Therefore follow the steps described in :ref:`quickstart-operation-guide`


