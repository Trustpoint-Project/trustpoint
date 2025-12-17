"""Tests for util/mult_obj_views.py."""

import pytest

from util.mult_obj_views import get_primary_keys_from_str_as_list_of_ints


class TestGetPrimaryKeysFromStrAsListOfInts:
    """Tests for get_primary_keys_from_str_as_list_of_ints function."""

    def test_single_primary_key(self) -> None:
        """Test parsing single primary key."""
        result = get_primary_keys_from_str_as_list_of_ints('123')
        assert result == [123]

    def test_multiple_primary_keys(self) -> None:
        """Test parsing multiple primary keys."""
        result = get_primary_keys_from_str_as_list_of_ints('1/2/3/4/5')
        assert result == [1, 2, 3, 4, 5]

    def test_with_trailing_slash(self) -> None:
        """Test parsing with trailing slash."""
        result = get_primary_keys_from_str_as_list_of_ints('10/20/30/')
        assert result == [10, 20, 30]

    def test_empty_string_raises_error(self) -> None:
        """Test that empty string raises ValueError."""
        with pytest.raises(ValueError, match='No primary keys found'):
            get_primary_keys_from_str_as_list_of_ints('')

    def test_duplicate_keys_raises_error(self) -> None:
        """Test that duplicate keys raise ValueError."""
        with pytest.raises(ValueError, match='Duplicates in query primary key list found'):
            get_primary_keys_from_str_as_list_of_ints('1/2/3/2/4')

    def test_duplicate_keys_with_trailing_slash_raises_error(self) -> None:
        """Test that duplicate keys with trailing slash raise ValueError."""
        with pytest.raises(ValueError, match='Duplicates in query primary key list found'):
            get_primary_keys_from_str_as_list_of_ints('5/10/5/')

    def test_non_integer_raises_error(self) -> None:
        """Test that non-integer values raise ValueError."""
        with pytest.raises(ValueError):
            get_primary_keys_from_str_as_list_of_ints('1/abc/3')

    def test_float_string_raises_error(self) -> None:
        """Test that float strings raise ValueError."""
        with pytest.raises(ValueError):
            get_primary_keys_from_str_as_list_of_ints('1/2.5/3')

    def test_negative_integers(self) -> None:
        """Test parsing negative integers."""
        result = get_primary_keys_from_str_as_list_of_ints('-1/-2/-3')
        assert result == [-1, -2, -3]

    def test_mixed_positive_negative(self) -> None:
        """Test parsing mixed positive and negative integers."""
        result = get_primary_keys_from_str_as_list_of_ints('1/-2/3/-4')
        assert result == [1, -2, 3, -4]

    def test_zero_as_primary_key(self) -> None:
        """Test parsing zero as primary key."""
        result = get_primary_keys_from_str_as_list_of_ints('0/1/2')
        assert result == [0, 1, 2]

    def test_large_numbers(self) -> None:
        """Test parsing large numbers."""
        result = get_primary_keys_from_str_as_list_of_ints('999999/1000000/1000001')
        assert result == [999999, 1000000, 1000001]

    def test_single_key_with_trailing_slash(self) -> None:
        """Test single key with trailing slash."""
        result = get_primary_keys_from_str_as_list_of_ints('42/')
        assert result == [42]

    def test_whitespace_in_keys_works(self) -> None:
        """Test that whitespace in keys is handled by int()."""
        # Python's int() handles leading/trailing whitespace
        result = get_primary_keys_from_str_as_list_of_ints('1/ 2 /3')
        assert result == [1, 2, 3]

    def test_many_primary_keys(self) -> None:
        """Test parsing many primary keys."""
        keys_str = '/'.join(str(i) for i in range(100))
        result = get_primary_keys_from_str_as_list_of_ints(keys_str)
        assert result == list(range(100))
        assert len(result) == 100
