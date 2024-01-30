import requests
import time
import random

from .general_utils import log_message


def make_request(method, url, headers, params, data, json, timeout):
    """Send an HTTP request and return the response."""
    return requests.request(method, url, headers=headers, params=params, data=data, json=json, timeout=timeout)


def should_retry(status_code, retry_codes=[]):
    """Check if the request should be retried based on the status code."""
    # Retry only server errors (5xx)
    if 500 <= status_code < 600 or status_code in retry_codes:
        return True


def calculate_backoff_time(attempt, base_backoff=1.0, max_time_to_wait=60, jitter_range=(1, 2)):
    """Calculate the exponential backoff time with jitter."""
    backoff_time = min(base_backoff * 2 ** (attempt - 1), max_time_to_wait)
    jitter = backoff_time * random.uniform(a=jitter_range[0], b=jitter_range[1])  # Add jitter
    return min(jitter, max_time_to_wait)
    # return backoff_time


def make_request_with_backoff(url, method='GET', headers=None, params=None, data=None, json=None, max_tries=5,
                              timeout=360, verbose=True, ratelimit_error_code=None):
    """
    Makes an HTTP request with a custom exponential backoff mechanism.
    """
    for attempt in range(1, max_tries + 1):
        try:
            response = make_request(method, url, headers, params, data, json, timeout)
            status_code = response.status_code

            if status_code == 200:
                return response
            elif not should_retry(status_code, retry_codes=([ratelimit_error_code])):
                log_message(verbose,
                            f"Non-retriable error (HTTP {status_code}) encountered on attempt {attempt}. Aborting...")
                log_message(verbose, f"Error message: {response.headers.get('message', None)}")
                return None

            log_message(verbose,
                        f"Retriable error (HTTP {status_code}) encountered on attempt {attempt}. Retrying after delay...")
            if rate_limit_reached(ratelimit_error_code, status_code):
                time.sleep(30)
                continue
            else:
                time.sleep(calculate_backoff_time(attempt))

        except requests.RequestException as e:
            log_message(verbose, f"Request exception on attempt {attempt}: {e}")
            if attempt == max_tries:
                log_message(verbose, "Max retries reached. Aborting...")
                return None
            time.sleep(calculate_backoff_time(attempt))

    log_message(verbose, "Max retries reached. Aborting...")
    return None


def rate_limit_reached(ratelimit_error_code, status_code):
    return ratelimit_error_code is not None and status_code == ratelimit_error_code