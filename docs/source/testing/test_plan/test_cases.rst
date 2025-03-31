Since we are using the :term:`BDD` principle for system and integration testing,
we decided on specifying the tests directly inside the :term:`Cucumber` feature files.
This has the advantage of removing the need to keep two or more documents updated at the same time.
Also, :term:`Gherkin` is a well organized language such that the test ideas and steps
are possible to read - even for people without a background in software engineering.
That being said, we state the feature files in the following and provide a brief description on the test ideas.

-----------------------
Functional Requirements
-----------------------

.. include:: test_plan/test_cases_func_req.rst

---------------------
Security Requirements
---------------------

.. include:: test_plan/test_cases_sec_req.rst

--------------------
Feature Requirements
--------------------

.. include:: test_plan/test_cases_feature_req.rst