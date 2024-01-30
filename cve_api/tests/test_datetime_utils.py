import unittest
from cve_api.utils.datetime_utils import get_older_date, convert_date_to_iso_format
from datetime import datetime


class TestDateFunctions(unittest.TestCase):
    def test_get_older_date(self):
        test_date = datetime(2021, 1, 10)
        older_date = get_older_date(test_date, 5)
        expected_date = datetime(2021, 1, 5)
        self.assertEqual(older_date, expected_date)

    def test_convert_date_to_iso_format(self):
        test_date = datetime(2021, 1, 1, 12, 0, 0)
        iso_date = convert_date_to_iso_format(test_date)
        self.assertEqual(iso_date, "2021-01-01T12:00:00")
