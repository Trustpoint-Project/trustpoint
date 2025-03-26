.. csv-table:: Suspension Criteria And Resumption Requirements
   :header: "Title", "Suspension", "Resumption"
   :widths: 30, 50, 50

    "Unavailability of CA or Domain Validation Services", "Testing will be paused if the certificate authority (CA) or domain validation services are unavailable, as these are critical for validating PKI-related functionalities.", "Testing will resume once the CA or validation services are operational, and any interrupted test cases will be re-executed to ensure completeness."
    "Critical Defect Identified in Core Functionality", "If a critical defect in core features (e.g., certificate issuance, revocation, or renewal) is identified during testing, further testing will be suspended until the issue is resolved.", "Testing will resume once the defect is fixed and verified in the development environment."
    "Test Environment Instability", "Testing will pause if the staging or testing environment becomes unstable or misconfigured, as this could lead to unreliable results.", "Testing will resume after the environment is restored to a stable and functional state, and necessary validations have been performed."
    "Unavailability of Required Test Data", "If critical test data (e.g., domain configurations, certificate requests) is unavailable or incomplete, testing will be suspended for the affected areas.", "Testing will resume once sufficient test data has been prepared and verified."
    "Staffing or Resource Constraints", "If key personnel (e.g., test managers or developers) or resources (e.g., access to tools or infrastructure) are unavailable, testing may be delayed for impacted areas.", "Testing will resume once adequate staffing and resources are available to continue the process effectively."
