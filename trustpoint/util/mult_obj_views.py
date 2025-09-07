"""This module contains helper functions for parsing HTTP GET and POST parameters."""


def get_primary_keys_from_str_as_list_of_ints(pks: str) -> list[int]:
    """Gets the primary keys for a str as list[str].

    Args:
        pks:
            The string in the form <pk0>/<pk1>/.../<pkn>.
             Duplicate primary keys will cause a ValueError.
            A trailing / is allowed.

    Raises:
        ValueError: If not all primary keys can be interpreted as integers or if duplicates where found.

    Returns:
        The list of primary keys.
    """
    if not pks:
        err_msg = 'No primary keys found, got an empty str.'
        raise ValueError(err_msg)
    pks_list = pks.split('/')

    # removing possible trailing empty string
    if pks_list[-1] == '':
        del pks_list[-1]

    if len(pks_list) != len(set(pks_list)):
        err_msg = 'Duplicates in query primary key list found.'
        raise ValueError(err_msg)

    return [int(pk) for pk in pks_list]
