import unittest
from cve_api.cve_fetcher import (
    get_default_api_params,
)

class MockResponse:
    def __init__(self, json_data, status_code=200, headers=None):
        self.json_data = json_data
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self.json_data


class TestCveFetcher(unittest.TestCase):
    def setUp(self):
        self.json_data = {}
        self.status_code = 200
        self.headers = {}
        self.url = "http://example.com"

    def test_get_default_api_params(self):
        base_url, max_days_per_request, results_per_page = get_default_api_params()
        self.assertEqual(base_url, "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.assertEqual(max_days_per_request, 120)
        self.assertEqual(results_per_page, 2000)
