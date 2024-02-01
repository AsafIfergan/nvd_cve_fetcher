import argparse
import os
from datetime import timedelta, datetime
import time

import cve_analyzer
from utils.fetching_utils import generate_start_indices
from utils.datetime_utils import get_date_params, convert_date_to_iso_format
from utils.request_utils import make_request_with_backoff
from utils.fetching_utils import (
    get_total_results_from_response,
    get_cves_from_response,
    save_results_to_jsons,
)
from utils.general_utils import (
    log_message,
    create_directory_with_parents,
    print_divider,
    cast_to_float,
)

"""
This script fetches data from the NVD API and saves it in json files.
The NVD API allows fetching data by date range, but the maximum allowed range is 120 days, so we need to divide the date range into multiple requests.
This limit of 120 days and the max 2000 results per page (as recommended in the documentation) can be changed in the get_default_api_params function.
More about the NVD API: https://nvd.nist.gov/developers
"""


def get_default_api_params():
    """
    Returns the default parameters for the NVD API.
    Args:
        None
    Returns:
        base_url (str): base url for the NVD API
        max_days_per_request (int): maximum days allowed per request
        results_per_page (int): maximum number of results to be returned per page
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    max_days_per_request = 120  # The maximum allowable range when using any date range parameters is 120 consecutive days.
    results_per_page = 2000  # as recommended by the NVD API documentation
    return base_url, max_days_per_request, results_per_page


def fetch_and_save_cves_in_daterange(
    endpoint: str, params: dict, output_directory: str, ratelimit_error_code=403
) -> None:
    """
    Fetches data from a specified endpoint with given parameters and saves it in the output directory.

    Args:
        endpoint (str): The API endpoint to fetch data from.
        params (dict): Parameters to be used in the API request.
        output_directory (str): Directory where the fetched data will be saved.
        ratelimit_error_code (int, optional): Error code to handle rate limiting. Defaults to 403 for the NVD API.
    """

    fetched_results = 0
    total_results = fetch_only_total_results(
        endpoint,
        params=params,
        custom_rate_limit_code=ratelimit_error_code,
        rate_limit_sleep_time=30,
    )
    results_per_page = params.get("resultsPerPage", 2000)

    for start_index in generate_start_indices(
        results_per_page, total_results
    ):  # this is a generator function
        params["startIndex"] = start_index
        response = make_request_with_backoff(
            endpoint,
            params=params,
            custom_rate_limit_code=ratelimit_error_code,
            rate_limit_sleep_time=30,
        )
        if not response:
            continue

        parsed_response = response.json()
        cve_list = get_cves_from_response(parsed_response)
        fetched_results += len(cve_list)
        save_results_to_jsons(
            cve_list=cve_list,
            output_directory=output_directory,
            items_per_json=results_per_page,
        )

    if not fetched_results == total_results:
        raise ValueError("fetched_results must be equal to total_results")


def fetch_only_total_results(
    endpoint, params, custom_rate_limit_code, rate_limit_sleep_time
):

    params_for_total_results = params.copy()
    params_for_total_results["resultsPerPage"] = 1
    initial_response = make_request_with_backoff(
        endpoint,
        params=params,
        custom_rate_limit_code=custom_rate_limit_code,
        rate_limit_sleep_time=rate_limit_sleep_time,
    )
    parsed_response = initial_response.json()
    total_results = get_total_results_from_response(parsed_response)
    return total_results


def fetch_all_data(
    start_date: datetime,
    end_date: datetime,
    max_days_per_request: int,
    base_url: str,
    output_directory: str,
    verbose=False,
    params: dict = None,
):
    """
    Fetches all data from the NVD API in a given date range and saves it in the output directory.
    Args:
        start_date (datetime): start date for to fetch data from
        end_date (datetime): end date to fetch data until
        max_days_per_request (int): maximum days allowed per request
        base_url (str): base url for the NVD API
        output_directory (str): directory where the fetched data will be saved
        verbose (bool, optional): whether to print messages to the console. Defaults to True.
        params (dict, optional): parameters to be used in the API request. Defaults to None.
    """

    if params is None:
        params = {}

    while start_date < end_date:
        # Calculate the end date for the current request
        current_request_end_date = min(
            start_date + timedelta(days=max_days_per_request), end_date
        )

        log_message(
            verbose,
            f"Fetching data for dates {start_date} to {current_request_end_date}",
        )

        # Format dates to ISO format for the API request
        iso_formatted_start_date = convert_date_to_iso_format(start_date)
        iso_formatted_end_date = convert_date_to_iso_format(current_request_end_date)

        # Update params and fetch data
        params.update(
            {
                "pubStartDate": iso_formatted_start_date,
                "pubEndDate": iso_formatted_end_date,
            }
        )
        try:
            fetch_and_save_cves_in_daterange(
                endpoint=base_url, params=params, output_directory=output_directory
            )
        except Exception:
            log_message(
                verbose,
                f"Failed to fetch data for dates {iso_formatted_start_date} to {iso_formatted_end_date}",
            )

        # Update the start date for the next iteration
        start_date = current_request_end_date + timedelta(
            microseconds=1
        )  # add 1 microsecond to avoid duplicates


def get_args():
    """Gets the arguments from the command line."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", default=None, required=True, type=str)
    parser.add_argument("--days-back", required=True, default=None, type=int)

    # these are flags - if they are present, they will be set to True. if they are not present, they will be set to False
    parser.add_argument("--verbose", required=False, default=False, action="store_true")
    parser.add_argument(
        "--no-analysis", required=False, default=False, action="store_true"
    )
    args = parser.parse_args()
    days_back = cast_to_float(args.days_back)
    if days_back is None:
        raise ValueError("days_back must be a numeric value")
    if days_back < 0:
        raise ValueError("days_back must be a positive value")
    return args


def print_script_run_info(output_directory, days_back, verbose, analyze):
    print(
        f"Starting data fetch with the following parameters:"
        f"\n  Output directory: {output_directory}"
        f"\n  Days back: {days_back}"
        f"\n  Verbose: {verbose}"
        f"\n  Run analysis: {analyze}"
    )


def main():
    start_time = time.time()

    args = get_args()
    output_directory = os.path.join(
        args.output_directory, "cves"
    )  # chose os over pathlib to reduce dependencies
    should_analyze = not args.no_analysis

    create_directory_with_parents(output_directory)

    base_url, max_days_per_request, results_per_page = get_default_api_params()

    params = {"resultsPerPage": results_per_page}
    start_date, end_date = get_date_params(args.days_back)
    fetch_all_data(
        start_date=start_date,
        end_date=end_date,
        max_days_per_request=max_days_per_request,
        base_url=base_url,
        output_directory=output_directory,
        verbose=args.verbose,
        params=params,
    )

    print(f"Done Fetching data, it is saved in {output_directory}")
    if should_analyze:
        cve_analyzer.run_analysis(output_directory)

    print_divider()
    end_time = time.time()
    log_message(args.verbose, f"Total runtime: {end_time - start_time} seconds")


if __name__ == "__main__":
    main()
