^^^^^
F_001
^^^^^

This testcase is related to requirement `F_001`_.

"""""""""
Test Idea
"""""""""

To verify that an NTEU (Non-Technical Experienced User) can successfully execute `R_001`_ and `R_002`_ in TPC_Web, we will test the following scenarios:

#. NTEU Logs into the System
    - A valid NTEU logs into the system successfully.
    - An invalid NTEU login attempt fails.

#. Identity Management (`R_001`_)
    - NTEU creates a digital identity.
    - NTEU views an existing digital identity.
    - NTEU edits an existing digital identity.
    - NTEU deletes a digital identity.

#. Zero-Touch Onboarding (`R_002`_)
    - NTEU initiates device onboarding.
    - The system automatically uses a zero-touch onboarding protocol.
    - The onboarding process completes successfully.

#. UI Accessibility and User Experience
    - The UI provides clear instructions and feedback.
    - Error messages are understandable for an NTEU.
    - The onboarding and identity management workflows are intuitive.

""""""""""""
Feature File
""""""""""""

.. literalinclude:: ../../../trustpoint/features/F_001_nteu_identity_onboarding.feature
   :language: gherkin