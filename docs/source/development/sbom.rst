.. _trustpoint_sbom:

=======================================
Trustpoint Software Bill of Materials
=======================================

-------------------------
Supported SBOM Formats
-------------------------

Trustpoint provides Software Bill of Materials (SBOMs) in the following formats:

- `SPDX (Software Package Data Exchange) <https://spdx.dev>`_
- `CycloneDX <https://cyclonedx.org>`_

These formats are widely adopted for secure software supply chain management and allow transparency around third-party dependencies, licenses, and vulnerabilities.

----------------------
SBOM Access and Links
----------------------

You can access the latest `Trustpoint SBOMs <https://trustpoint-project.github.io/trustpoint/sbom/>`_ here:

^^^^^^^^^^
SPDX SBOM
^^^^^^^^^^

The SPDX-formatted SBOM is available in JSON format: `Download SPDX SBOM <https://trustpoint-project.github.io/trustpoint/sbom/latest/trustpoint.spdx.json>`_ (latest)

^^^^^^^^^^^^^^^
CycloneDX SBOM
^^^^^^^^^^^^^^^

The CycloneDX-formatted SBOM is available in JSON format: `Download CycloneDX SBOM <https://trustpoint-project.github.io/trustpoint/sbom/latest/trustpoint.cyclonedx.json>`_ (latest)

--------------------------------------
SBOM Generation and CI Integration
--------------------------------------

The SBOMs are **automatically generated** and kept up to date via a `GitHub Actions Workflow <https://github.com/Trustpoint-Project/trustpoint/blob/main/.github/workflows/sbom.yml>`_.

The joint GHCR/Docker Hub publisher (``publish-images.yml``) calls this workflow
after publishing images from ``main``,
release tags, or a manual build. Syft scans the published image by its immutable
SHA-256 digest from GHCR, rather than rebuilding it. Both registries receive the
same build. The publisher uses the existing ``DOCKER_HUB_USERNAME`` and
``DOCKER_HUB_ACCESS_TOKEN`` repository secrets. Version directories are retained
under ``sbom/``. A manual SBOM run requires an image reference including its
digest and a release tag or commit identifier.

----------------------
Validation and Tools
----------------------

You may use the following tools to validate or inspect the SBOMs:

- `SPDX Tools <https://github.com/spdx/tools>`_
- `cyclonedx-cli <https://github.com/CycloneDX/cyclonedx-cli>`_
- `syft <https://github.com/anchore/syft>`_

These tools allow validation, transformation, and comparison of SBOMs to meet compliance and operational requirements.

