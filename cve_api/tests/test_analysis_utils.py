import unittest
from cve_api.utils.analysis_utils import iterate_cves, count_affected_packages
from cve_api.utils.general_utils import load_json


class TestAnalysisUtils(unittest.TestCase):
    def setUp(self):
        self.test_cves_data = load_json(
            "test_files/mock_output_directory/cves_test_file.json"
        )
        self.single_cve_data = load_json("test_files/single_cve.json").get("cve", None)

    def test_iterate_cves(self):
        # Mock data for testing

        expected_number_of_cevs = 660
        yielded_cev_count = 0
        for cve in iterate_cves(self.test_cves_data):
            self.assertIsInstance(cve, dict)
            yielded_cev_count += 1

        self.assertEqual(yielded_cev_count, expected_number_of_cevs)

    def test_count_affected_packages(self):

        # Expected results
        expected_count = {"eric_allman_sendmail": 1}

        # Test
        result = count_affected_packages(self.single_cve_data)
        self.assertEqual(result, expected_count)


if __name__ == "__main__":
    unittest.main()
