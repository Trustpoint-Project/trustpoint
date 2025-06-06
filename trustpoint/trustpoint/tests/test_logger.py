import logging
import pytest
from trustpoint.logger import LoggerMixin


@pytest.fixture
def sample_class():
    """Fixture providing a sample class that uses LoggerMixin."""
    class SampleClass(LoggerMixin):
        pass

    return SampleClass


class TestLoggerMixin:
    """Pytest-based test suite for LoggerMixin."""

    def test_logger_initialization(self, sample_class):
        """Verify that LoggerMixin initializes a logger correctly."""
        assert hasattr(sample_class, "logger"), "LoggerMixin should add a 'logger' attribute"
        assert isinstance(sample_class.logger, logging.Logger), "Logger should be an instance of logging.Logger"

    def test_logger_hierarchy(self, sample_class):
        """Verify that the logger hierarchy is set up correctly."""
        expected_logger_name = f"trustpoint.{sample_class.__module__}.{sample_class.__name__}"
        logger_name = sample_class.logger.name
        assert logger_name == expected_logger_name, (
            f"Expected logger name '{expected_logger_name}', but got '{logger_name}'"
        )

    def test_logger_different_classes_have_different_loggers(self, sample_class):
        """Ensure that separate classes using LoggerMixin have distinct loggers."""
        class AnotherSampleClass(LoggerMixin):
            pass

        logger_1 = sample_class.logger
        logger_2 = AnotherSampleClass.logger

        assert logger_1 != logger_2, (
            f"Loggers should be distinct for separate classes. Found the same: {logger_1.name}"
        )
        assert logger_1.name != logger_2.name, (
            f"Logger names should differ for distinct classes. "
            f"Found: {logger_1.name} and {logger_2.name}"
        )

    def test_logger_correct_in_nested_modules(self):
        """Verify proper logger hierarchy in nested modules."""

        class MockModule:
            class SampleClass(LoggerMixin):
                pass

        expected_logger_name = f"trustpoint.{MockModule.SampleClass.__module__}.{MockModule.SampleClass.__name__}"
        assert MockModule.SampleClass.logger.name == expected_logger_name, (
            f"Expected logger name '{expected_logger_name}', but got '{MockModule.SampleClass.logger.name}'"
        )


