Frequently Asked Questions (FAQ)
================================

What is Trustpoint?
-------------------
Trustpoint is an open-source platform designed to simplify and enhance public key infrastructure (PKI) management.
It aims to deliver secure, efficient,
and scalable solutions for managing digital certificates, domains, and security protocols for industrial environments.

Who can benefit from Trustpoint?
--------------------------------
Trustpoint is tailored for industrial users, particularly in mechanical engineering and manufacturing industries,
who require efficient management of digital identities and certificates.


Who is (mainly) developing Trustpoint?
--------------------------------------
The development team comprises:

- **Companies:**
  - achelos
  - asvin

- **Research Institutions and Universities:**
  - Campus Schwarzwald
  - Hochschule Hamm-Lippstadt

Who are the associated partners of Trustpoint?
-------------------------------------------------
Associated partners include:

- ARBURG GmbH + Co KG
- Belden Inc.
- HOMAG GmbH
- Phoenix Contact
- J. Schmalz GmbH
- Siemens AG
- Diebold Nixdorf


How is Trustpoint funded?
----------------------------
Trustpoint is funded by the German Federal Ministry of Education and Research since September 2023.

How can I ask questions or provide feedback about Trustpoint?
----------------------------------------------------------------
You can ask questions in the Discussions section of the GitHub repository, and the team will respond.
Additionally, suggestions can be sent to `trustpoint@campus-schwarzwald.de`.

What technologies does Trustpoint use?
-----------------------------------------
The current version of Trustpoint uses a Python Django framework.

How can I set up the development environment for Trustpoint?
---------------------------------------------------------------
To set up the development environment, follow the steps in :ref:`trustpoint_dev_env_setup`.

How can I build and run Trustpoint using Docker?
---------------------------------------------------
To build and run Trustpoint as a Docker image:

- **Build the Docker Image**: Navigate to the project's root directory and run:

  .. code-block:: bash

     docker build -t trustpoint .

- **Run the Docker Container**: Once the image is built, run:

  .. code-block:: bash

     docker run -d --name trustpoint-container -p 80:80 -p 443:443 trustpoint

How can I contribute to the Trustpoint project?
--------------------------------------------------
Contributions are welcome. You can fork the repository, make your changes, and submit a pull request.
Ensure that your contributions align with the `project's guidelines and standards <https://github.com/TrustPoint-Project/trustpoint/blob/main/AUTHORS.md>`_.

1. What license does Trustpoint use?
------------------------------------
Trustpoint is released under the MIT license.
This allows for broad usage, modification, and distribution of the software, promoting open collaboration and development.
You can find the license `here <https://github.com/TrustPoint-Project/trustpoint/blob/main/LICENSE>`_
