import unittest
from cve_api.utils.request_utils import (
    calculate_backoff_time,
    should_retry,
    make_request,
    get_backoff_with_jitter,
    make_request_with_backoff,
    is_ratelimit_reached,
    sleep_on_retry,
)
from unittest.mock import patch


class TestRequestUtils(unittest.TestCase):
    def setUp(self):
        self.url = "http://example.com"
        self.method = "GET"
        self.headers = None
        self.params = None
        self.data = None
        self.json = None
        self.max_tries = 5
        self.timeout = 360
        self.verbose = True
        self.custom_rate_limit_code = None
        self.rate_limit_sleep_time = None

    @patch("requests.request")
    def test_make_request_success(self, mock_request):
        mock_request.return_value.status_code = 200
        response = make_request(
            self.method,
            self.url,
            self.headers,
            self.params,
            self.data,
            self.json,
            self.timeout,
        )
        self.assertEqual(response.status_code, 200)

    @patch("requests.request")
    def test_make_request_failure(self, mock_request):
        mock_request.return_value.status_code = 500
        response = make_request(
            self.method,
            self.url,
            self.headers,
            self.params,
            self.data,
            self.json,
            self.timeout,
        )
        self.assertEqual(response.status_code, 500)

    @patch("requests.request")
    def test_make_request_with_backoff_success(self, mock_request):
        mock_request.return_value.status_code = 200
        response = make_request_with_backoff(
            self.url,
            self.method,
            self.headers,
            self.params,
            self.data,
            self.json,
            self.max_tries,
            self.timeout,
            self.verbose,
            self.custom_rate_limit_code,
            self.rate_limit_sleep_time,
        )
        self.assertEqual(response.status_code, 200)

    @patch("requests.request")
    @patch("time.sleep")  # Mock time.sleep to avoid actual sleep
    def test_make_request_with_backoff_failure(self, mock_request, mock_sleep):
        mock_request.return_value.status_code = 500
        response = make_request_with_backoff(
            self.url,
            self.method,
            self.headers,
            self.params,
            self.data,
            self.json,
            self.max_tries,
            self.timeout,
            self.verbose,
            self.custom_rate_limit_code,
            self.rate_limit_sleep_time,
        )
        self.assertIsNone(response)

    def test_calculate_backoff_time(self):
        # Test with different attempts
        self.assertEqual(calculate_backoff_time(1), 1)
        self.assertEqual(calculate_backoff_time(2), 2)
        self.assertEqual(calculate_backoff_time(3), 4)
        self.assertEqual(calculate_backoff_time(4), 8)
        self.assertEqual(calculate_backoff_time(5), 16)

        # Test with a different base backoff
        self.assertEqual(calculate_backoff_time(2, base_backoff=2), 4)
        self.assertEqual(calculate_backoff_time(3, base_backoff=2), 8)
        self.assertEqual(calculate_backoff_time(4, base_backoff=5), 40)

        # Test with max time to wait
        self.assertEqual(calculate_backoff_time(100, max_time_to_wait=5), 5)

    @patch("random.uniform")
    def test_get_backoff_with_jitter(self, mock_random):
        mock_random.return_value = 1.5

        # Test with default jitter range
        self.assertEqual(get_backoff_with_jitter(1), 2.5)

        # Test with max time to wait
        self.assertEqual(get_backoff_with_jitter(10, max_time_to_wait=30), 30)

        # Test with different base backoff
        self.assertEqual(get_backoff_with_jitter(2, base_backoff=2), 5.5)

        # Test with higher number of attempts
        self.assertEqual(get_backoff_with_jitter(5), min(16 + 1.5, 60))

        # Test with backoff time equals max time to wait
        self.assertEqual(get_backoff_with_jitter(6, max_time_to_wait=32), 32)

        # Test with zero attempts
        self.assertRaises(ValueError, get_backoff_with_jitter, 0)

        # Test with negative attempts
        self.assertRaises(ValueError, get_backoff_with_jitter, -1)

    def test_is_ratelimit_reached(self):
        self.assertTrue(is_ratelimit_reached(429, 429))
        self.assertFalse(is_ratelimit_reached(200, 429))
        self.assertFalse(is_ratelimit_reached(429))
        self.assertFalse(is_ratelimit_reached(None))

    @patch("time.sleep")  # Mock time.sleep to avoid actual sleep
    @patch("random.uniform")
    def test_sleep_on_retry(self, mock_random, mock_sleep):
        # Set the return value for the random jitter
        mock_random.return_value = 1.5

        # First scenario: Custom rate limit code matches, should sleep for the rate limit sleep time
        sleep_on_retry(429, 429, 1, 5)
        mock_sleep.assert_called_with(
            5
        )  # Assert that sleep was called with rate limit sleep time

        # Resetting mock to check the next call independently
        mock_sleep.reset_mock()

        # Second scenario: No custom rate limit code, should sleep for the calculated backoff time
        sleep_on_retry(None, 500, 1, 5)

    def test_should_retry(self):
        # Test with retryable status codes
        self.assertTrue(should_retry(500))
        self.assertTrue(should_retry(503))
        # Test with custom rate limit code
        self.assertTrue(should_retry(429, 429))
        self.assertFalse(should_retry(429, 428))
        self.assertFalse(should_retry(429))
        self.assertFalse(should_retry(None))
        # Test with other status codes
        self.assertFalse(should_retry(200))
        self.assertFalse(should_retry(404))
