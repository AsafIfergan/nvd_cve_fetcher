import argparse
import os
from datetime import timedelta, datetime
import time
import subprocess

from utils.datetime_utils import get_dates, convert_date_to_iso_format
from utils.request_utils import make_request_with_backoff
from utils.fetching_utils import get_total_results, get_cves_from_response, save_results_to_jsons
from utils.general_utils import log_message, create_directory_with_parents, print_divider

"""
This script fetches data from the NVD API and saves it in json files.
The NVD API allows fetching data by date range, but the maximum allowed range is 120 days, so we need to divide the date range into multiple requests.
This limit of 120 days and the max 2000 results per page (as recommended in the documentation) can be changed in the get_default_api_params function.
More about the NVD API: https://nvd.nist.gov/developers
"""


def get_default_api_params():
    max_days_per_request = 120  # Maximum days allowed per request. Found out the hard way.
    max_results_per_page = 2000  # as recommended by the NVD API documentation
    return max_days_per_request, max_results_per_page


def fetch_and_save_data(endpoint: str, params: dict, output_directory: str, ratelimit_error_code=403) -> None:
    """
        Fetches data from a specified endpoint with given parameters and saves it in the output directory.

        Args:
            endpoint (str): The API endpoint to fetch data from.
            params (dict): Parameters to be used in the API request.
            output_directory (str): Directory where the fetched data will be saved.
            ratelimit_error_code (int, optional): Error code to handle rate limiting. Defaults to 403.

        Returns:
            dict: A dictionary containing the results of the data fetch operation.
        """

    max_results_per_page = params['resultsPerPage']
    total_results = 100  # arbitrary number to start loop
    start_index = 1

    while start_index <= total_results:
        params['startIndex'] = start_index
        response = make_request_with_backoff(endpoint, params=params,
                                             ratelimit_error_code=ratelimit_error_code)  # 403 seems to be the error code for exceeded rate limits in this API
        if not response:
            continue

        parsed_response = response.json()
        total_results = get_total_results(parsed_response)
        start_index += max_results_per_page
        cve_list = get_cves_from_response(parsed_response)
        save_results_to_jsons(cve_list=cve_list, output_directory=output_directory, items_per_json=max_results_per_page)


def paginate_dates(start_date: datetime, end_date: datetime, max_days_per_request: int, base_url: str,
                   output_directory: str,
                   verbose=True, params: dict = {}):
    while start_date < end_date:
        current_request_end_date = min(start_date + timedelta(days=max_days_per_request), end_date)
        log_message(verbose, f"Fetching CVEs published between {start_date} and {end_date}")
        iso_formatted_start_date = convert_date_to_iso_format(start_date)
        iso_formatted_end_date = convert_date_to_iso_format(current_request_end_date)
        params.update({"pubStartDate": iso_formatted_start_date, "pubEndDate": iso_formatted_end_date})
        fetch_and_save_data(endpoint=base_url, params=params, output_directory=output_directory)
        start_date = current_request_end_date


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", default=None, required=True, type=str)
    parser.add_argument("--days-back", required=True, default=None)

    # these are flags - if they are present, they will be set to True. if they are not present, they will be set to False
    parser.add_argument("--verbose", required=False, default=False, action='store_true')
    parser.add_argument("--no-analysis", required=False, default=False, action='store_true')
    args = parser.parse_args()
    args.days_back = int(args.days_back) if args.days_back.isdigit() else None
    validate_args(args)  # this will raise an exception if the args are invalid
    return args


def validate_args(args):
    assert isinstance(args.days_back, int), "days_back must be an integer"
    assert args.days_back > 0, "days_back must be greater than 0"
    assert isinstance(args.verbose, bool), "verbose must be a boolean"
    assert isinstance(args.no_analysis, bool), "run_analysis must be a boolean"
    return True


def main():
    start_time = time.time()
    args = get_args()
    output_directory = os.path.join(args.output_directory, "cves")  # chose os over pathlib to reduce dependencies
    days_back = args.days_back
    verbose = args.verbose
    analyze = not args.no_analysis
    print(
        f"Starting data fetch with the following parameters:"
        f"\n  Output directory: {output_directory}"
        f"\n  Days back: {days_back}"
        f"\n  Verbose: {verbose}"
        f"\n  Run analysis: {analyze}"
    )

    create_directory_with_parents(output_directory)
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    max_days_per_request, max_results_per_page = get_default_api_params()

    params = {"resultsPerPage": max_results_per_page}
    start_date, end_date = get_dates(days_back)
    paginate_dates(start_date=start_date, end_date=end_date, max_days_per_request=max_days_per_request,
                   base_url=base_url, output_directory=output_directory, verbose=verbose, params=params)

    print(f"Done! Fetched data is saved in {output_directory}")
    if analyze:
        subprocess.run(['python', './cve_api/analyze.py', '--output-directory', output_directory])

    print_divider()
    end_time = time.time()
    log_message(verbose, f"Total runtime: {end_time - start_time} seconds")


if __name__ == "__main__":
    main()
