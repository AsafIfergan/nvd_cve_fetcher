import unittest
from cve_api.utils.fetching_utils import (
    get_total_results_from_response,
    save_results_to_jsons,
    generate_start_indices,
)


class TestFetcherUtils(unittest.TestCase):
    def test_get_total_results_with_valid_input(self):
        response = {"totalResults": "100"}
        result = get_total_results_from_response(response)
        self.assertEqual(result, 100)
        response = {}
        result = get_total_results_from_response(response)
        self.assertIsNone(result)
        response = {"totalResults": "invalid"}
        result = get_total_results_from_response(response)
        self.assertIsNone(result)
        response = {"totalResults": None}
        result = get_total_results_from_response(response)
        self.assertIsNone(result)

    def test_generate_start_indices(self):
        results_per_page = 10
        total_results = 35
        expected_indices = [0, 10, 20, 30]
        result = list(generate_start_indices(results_per_page, total_results))
        self.assertEqual(result, expected_indices)
        # Test with total_results = 0
        results_per_page = 10
        total_results = 0
        expected_indices = [0]
        result = list(generate_start_indices(results_per_page, total_results))
        self.assertEqual(result, expected_indices)
