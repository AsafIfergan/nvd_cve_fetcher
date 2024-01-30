import unittest
from cve_api.analyze import get_jsons_analysis
from cve_api.utils.general_utils import load_json

class TestAnalyzeE2E(unittest.TestCase):

    def setUp(self):
        self.test_jsons_path = "test_files/mock_output_directory"

    def test_analysis(self):

        total_average, severities, top_affected_packages = get_jsons_analysis(self.test_jsons_path)

        expected_total_average = 6.59004149377592
        expected_severities = {'medium': 156, 'high': 63, 'critical': 18, 'low': 4}
        expected_top_affected_packages = [('myq-solution_print_server', 48), ('ajaysharma_cups_easy', 41),
                                          ('apple_macos', 32), ('appleple_a-blog_cms', 25), ('linecorp_line', 23)]

        self.assertEqual(total_average, expected_total_average)
        self.assertEqual(severities, expected_severities)
        self.assertEqual(top_affected_packages, expected_top_affected_packages)

if __name__ == '__main__':
    unittest.main()
