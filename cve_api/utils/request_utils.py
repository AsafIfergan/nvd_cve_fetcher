import requests
import time
import random

from .general_utils import log_message, cast_to_float


def make_request_with_backoff(
    url,
    method="GET",
    headers=None,
    params=None,
    data=None,
    json=None,
    max_tries=5,
    timeout=360,
    verbose=True,
    custom_rate_limit_code=None,
    rate_limit_sleep_time=None,
):
    """
    Makes an HTTP request with a custom exponential backoff mechanism.
    Args:
        url (str): url for the request
        method (str, optional): HTTP method. Defaults to 'GET'.
        headers (dict, optional): HTTP headers. Defaults to None.
        params (dict, optional): HTTP parameters. Defaults to None.
        data (dict, optional): HTTP data. Defaults to None.
        json (dict, optional): HTTP json. Defaults to None.
        max_tries (int, optional): maximum number of tries. Defaults to 5.
        timeout (int, optional): timeout for the request. Defaults to 360.
        verbose (bool, optional): whether to print messages to the console. Defaults to True.
        custom_rate_limit_code (int, optional): custom rate limit code. Defaults to None.
        rate_limit_sleep_time (int, optional): time to sleep if the rate limit has been reached. Defaults to None.
    """
    for attempt in range(1, max_tries + 1):

        try:
            response = make_request(method, url, headers, params, data, json, timeout)
            status_code = response.status_code

            if status_code == 200:
                return response

            elif not should_retry(status_code, custom_rate_limit_code):
                return None

            log_message(
                verbose,
                f"Retryable error (HTTP {status_code}) encountered on attempt {attempt}. Retrying after delay...",
            )

            sleep_on_retry(
                custom_rate_limit_code, status_code, attempt, rate_limit_sleep_time
            )
            continue

        except requests.RequestException as e:
            log_message(verbose, f"Request exception on attempt {attempt}: {e}")
            time.sleep(calculate_backoff_time(attempt))

    log_message(verbose, "Max retries reached. Aborting...")
    return None


def make_request(method, url, headers, params, data, json, timeout):
    """Send an HTTP request and return the response."""
    return requests.request(
        method,
        url,
        headers=headers,
        params=params,
        data=data,
        json=json,
        timeout=timeout,
    )


def is_ratelimit_reached(status_code, custom_rate_limit_code=None):
    """Check if the rate limit has been reached based on the status code.
    Args:
        status_code (int): status code of the response
        custom_rate_limit_code (int, optional): custom rate limit code. Defaults to None.
    Returns:
        bool: whether the rate limit has been reached
    """
    if custom_rate_limit_code is not None and status_code == custom_rate_limit_code:
        return True
    else:
        return False


def sleep_on_retry(custom_rate_limit_code, status_code, attempt, rate_limit_sleep_time):
    """Sleep on retry.
    Args:
        custom_rate_limit_code (int, optional): custom rate limit code. Defaults to None.
        status_code (int): status code of the response
        attempt (int): attempt number
        rate_limit_sleep_time (int): time to sleep if the rate limit has been reached
    """
    if (
        is_ratelimit_reached(custom_rate_limit_code, status_code)
        and rate_limit_sleep_time is not None
    ):
        time.sleep(rate_limit_sleep_time)
    else:
        time.sleep(calculate_backoff_time(attempt))


def should_retry(status_code, custom_rate_limit_code=None):
    """Check if the request should be retried based on the status code.
    Args:
        status_code (int): status code of the response
        custom_rate_limit_code (int, optional): custom rate limit code. Defaults to None.
    Returns:
        bool: whether the request should be retried
    """
    status_code = cast_to_float(status_code)
    if status_code is None:
        return False
    if 500 <= status_code < 600:
        return True
    elif custom_rate_limit_code is not None and status_code == custom_rate_limit_code:
        return True
    else:
        return False


def calculate_backoff_time(attempt, base_backoff=1.0, max_time_to_wait=60):
    """Calculate the backoff time for a request.
    Args:
        attempt (int): attempt number
        base_backoff (float, optional): base backoff time. Defaults to 1.0.
        max_time_to_wait (int, optional): maximum time to wait. Defaults to 60.
    Returns:
        float: backoff time
    """
    backoff_time = min(base_backoff * 2 ** (attempt - 1), max_time_to_wait)
    return backoff_time


def get_backoff_with_jitter(
    attempt, base_backoff=1.0, max_time_to_wait=60, jitter_range=(1, 2)
):
    """Calculate the backoff time for a request with jitter.
    Args:
        attempt (int): attempt number
        base_backoff (float, optional): base backoff time. Defaults to 1.0.
        max_time_to_wait (int, optional): maximum time to wait. Defaults to 60.
        jitter_range (tuple, optional): jitter range. Defaults to (1, 2).
    Returns:
        float: backoff time with jitter
    """
    if attempt < 1:
        raise ValueError("attempt must be greater than or equal to 1")

    backoff_time = calculate_backoff_time(attempt, base_backoff, max_time_to_wait)
    backoff_time_with_jitter = backoff_time + random.uniform(
        jitter_range[0], jitter_range[1]
    )
    return min(backoff_time_with_jitter, max_time_to_wait)
