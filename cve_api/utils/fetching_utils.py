import os
from .general_utils import save_json, yield_list_chunks, cast_to_float


def get_total_results_from_response(parsed_response: dict) -> int:
    """Gets the total number of results from a parsed response.
    Args:
        parsed_response (dict): parsed response from the API
        Returns:
            int: total number of results for the request
    """
    total_results = parsed_response.get("totalResults", None)
    if cast_to_float(total_results) is not None:
        return int(total_results)


def get_cves_from_response(parsed_response: dict) -> list:
    """Gets a list of CVEs from a parsed response.
    Args:
        parsed_response (dict): parsed response from the API
        Returns:
            list: list of CVEs
    """
    return parsed_response.get("vulnerabilities", None)


def save_results_to_jsons(
    cve_list: list, output_directory: str, items_per_json: int
) -> None:
    """Saves a list of CVEs to multiple json files.
    Args:
        cve_list (list): list of CVEs to be saved
        output_directory (str): directory where the json files will be saved
        items_per_json (int): number of items to be saved in each json file"""

    chunks_to_save = yield_list_chunks(cve_list, chunk_size=items_per_json)
    for chunk in chunks_to_save:
        # naming convention: first_cve_publish_date_last_cve_publish_date.json
        # this can allow building a caching mechanism in the future

        (
            first_cve_publish_date,
            last_cve_publish_date,
        ) = get_first_and_last_cve_publish_date(chunk)

        filename = f"from_{first_cve_publish_date}_to_{last_cve_publish_date}.json"
        filepath = os.path.join(output_directory, filename)
        if not os.path.exists(filepath):
            save_json(filepath, chunk)


def get_first_and_last_cve_publish_date(chunk: list) -> None:
    """Gets the first and last CVE publish date from a list of CVEs.
    Args:
        chunk (list): list of CVEs
        Returns:
            first and last CVE publish dates
    """

    if not isinstance(chunk, list):
        raise ValueError("chunk must be a list")
    if len(chunk) == 0:
        raise ValueError("chunk must not be empty")
    first_cve_publish_date = chunk[0].get("cve").get("published", None)
    last_cve_publish_date = chunk[-1].get("cve").get("published", None)

    return first_cve_publish_date, last_cve_publish_date


def generate_start_indices(results_per_page, total_results):
    """a generator function that yields start indices for paginating requests.
        The CVE index is zero-based.
    Args:
        results_per_page (int): number of results to be returned per page
        total_results (int): total number of results to be fetched

        Yields:
            int: start index for the next page of results
    """
    if total_results is not None:
        for start_index in range(0, total_results + 1, results_per_page):
            yield start_index
    else:
        raise ValueError("total_results must be a numeric value but is None")
