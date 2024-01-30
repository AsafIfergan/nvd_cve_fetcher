import unittest
from unittest.mock import patch, mock_open
from cve_api.utils.general_utils import (
    create_directory_with_parents,
    cast_to_float,
    save_json,
    yield_list_chunks,
    calculate_numeric_array_average,
)


class TestGeneralUtils(unittest.TestCase):
    @patch("os.makedirs")
    def test_create_directory_with_parents(self, mock_makedirs):
        directory_path = "/test/directory"
        create_directory_with_parents(directory_path)
        mock_makedirs.assert_called_with(directory_path, exist_ok=True)

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    @patch("cve_api.utils.general_utils.log_message")
    def test_save_json(self, mock_log_message, mock_json_dump, mock_file):
        filepath = "/path/to/file.json"
        cve_list = ["CVE-1234", "CVE-5678"]
        save_json(filepath, cve_list, verbose=True)
        mock_file.assert_called_with(filepath, "w")
        mock_json_dump.assert_called_with(cve_list, mock_file(), indent=4)
        mock_log_message.assert_called_with(
            True, f"Successfully saved results to {filepath}"
        )

    @patch("builtins.open", new_callable=mock_open)
    @patch("json.dump")
    @patch("cve_api.utils.general_utils.log_message")
    def test_save_json_failure(self, mock_log_message, mock_json_dump, mock_file):
        mock_file.side_effect = IOError(
            "Failed to open file"
        )  # Simulate a file open failure
        filepath = "/path/to/file.json"
        cve_list = ["CVE-1234", "CVE-5678"]
        save_json(filepath, cve_list, verbose=True)

        mock_log_message.assert_called_with(
            True, f"Failed to save results to {filepath}"
        )
        # Check that json.dump was not called since opening the file failed
        mock_json_dump.assert_not_called()

    def test_yield_list_chunks(self):
        all_cves = list(range(100))
        chunk_size = 10
        chunks = list(yield_list_chunks(all_cves, chunk_size))
        self.assertEqual(len(chunks), 10)
        self.assertEqual(len(chunks[0]), 10)
        self.assertEqual(chunks[0], list(range(10)))
        self.assertEqual(chunks[-1], list(range(90, 100)))

    def test_calculate_numeric_array_average(self):
        array = [1, 2, 3, 4, 5]
        result = calculate_numeric_array_average(array)
        self.assertEqual(result, 3.0)
        array = [1, 2, 3, 4, 5, "invalid"]
        result = calculate_numeric_array_average(array)
        self.assertEqual(result, 3.0)
        array = [1, 2, 3, 4, 5, None]
        result = calculate_numeric_array_average(array)
        self.assertEqual(result, 3.0)
        array = []
        result = calculate_numeric_array_average(array)
        self.assertEqual(result, 0)
        array = None
        result = calculate_numeric_array_average(array)
        self.assertEqual(result, 0)

    def test_cast_to_float(self):
        self.assertEqual(cast_to_float("3.14"), 3.14)
        self.assertEqual(cast_to_float(3.14), 3.14)
        self.assertEqual(cast_to_float(3), 3.0)
        self.assertEqual(cast_to_float("-35"), -35.0)
        self.assertEqual(cast_to_float("invalid"), None)
        self.assertEqual(cast_to_float(None), None)
