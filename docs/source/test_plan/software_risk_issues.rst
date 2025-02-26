All software testing involves risks, which are listed below in order to minimize them.

- *Incomplete requirements:*
    As Trustpoint is a research project,
    it can happen that requirements are incomplete and only become apparent in retrospect that they would have been important.

- *Incomplete test coverage:*
    Although we strive to keep the test coverage as high as possible,
    sometimes not everything can be tested.
    As a result, some execution paths may be left out,
    with the resulting problems only becoming apparent during productive operation.

- *Lack of time for testing:*
    It could well happen that the test plan is too long and complex,
    so that we run out of time with the software tests.

- *Problems with the test environment:*
    Not every (automated) test can be carried out on a real environment.
    Therefore, simulation components are likely to be used,
    but these will probably not represent exactly the same devices as they will look like in the production environment.
    An example of this would be the simulation or integration of older machines which do not provide a certificate signed by the manufacturer.

- *User-friendliness:*
    The testers of the program's interface (acceptance testing) should be people with as little technical knowledge as possible,
    as otherwise the tests may give a false picture when tested by people from the development team.

- *Problems with manual testing:*
    We should thrive for automatic testing, although not every requirement can be tested automatically.
    That is, because the manual testing techniques are sometimes but not always the root of an error.