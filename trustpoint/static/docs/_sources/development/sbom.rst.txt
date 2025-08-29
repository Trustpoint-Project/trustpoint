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

You can access the latest Trustpoint SBOMs here:

^^^^^^^^^^
SPDX SBOM
^^^^^^^^^^

The SPDX-formatted SBOM is available in JSON format: `Download SPDX SBOM <https://github.com/Trustpoint-Project/trustpoint/blob/main/sbom_spdx.json>`_

^^^^^^^^^^^^
CycloneDX SBOM
^^^^^^^^^^^^

The CycloneDX-formatted SBOM is available in JSON format: `Download CycloneDX SBOM <https://github.com/Trustpoint-Project/trustpoint/blob/main/sbom_cyclonedx.json>`_

--------------------------------------
SBOM Generation and CI Integration
--------------------------------------

The SBOMs are **automatically generated** and kept up to date via a `GitHub Actions Workflow <https://github.com/Trustpoint-Project/trustpoint/blob/main/.github/workflows/sbom.yml>`_.

This workflow is triggered **on every push to the `main` branch**, ensuring that the published SBOMs always reflect the current state of the codebase and its dependencies.

----------------------
Validation and Tools
----------------------

You may use the following tools to validate or inspect the SBOMs:

- `SPDX Tools <https://github.com/spdx/tools>`_
- `cyclonedx-cli <https://github.com/CycloneDX/cyclonedx-cli>`_
- `syft <https://github.com/anchore/syft>`_

These tools allow validation, transformation, and comparison of SBOMs to meet compliance and operational requirements.

