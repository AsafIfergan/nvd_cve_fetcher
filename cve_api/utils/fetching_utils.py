import os
from utils.general_utils import save_json, yield_list_chunks


def get_total_results(parsed_response: dict) -> int:
    # unit test this function

    total_results = parsed_response.get('totalResults', None)
    if total_results is None:
        return 0

    if isinstance(total_results, str):
        if total_results.isdigit():
            return int(total_results)
    elif isinstance(total_results, (int, float)):
        return int(total_results)

def get_cves_from_response(parsed_response: dict) -> list:
    return parsed_response.get('vulnerabilities', None)

def save_results_to_jsons(cve_list: list, output_directory: str, items_per_json: int) -> None:
    """ Saves a list of CVEs to multiple json files.
    Args:
        cve_list (list): list of CVEs to be saved
        output_directory (str): directory where the json files will be saved
        items_per_json (int): number of items to be saved in each json file"""

    chunks_to_save = yield_list_chunks(cve_list, chunk_size=items_per_json)
    for chunk in chunks_to_save:
        # naming convention: first_cve_publish_date_last_cve_publish_date.json. this will allow us to sort by date and not fetch the same data twice

        first_cve_publish_date, last_cve_publish_date = get_first_and_last_cve_publish_date(chunk)

        filename = f"from_{first_cve_publish_date}_to_{last_cve_publish_date}.json"
        filepath = os.path.join(output_directory, filename)
        if not os.path.exists(filepath):
            save_json(filepath, chunk)
        else:
            print(f"{filepath} already exists. Skipping...")

def get_first_and_last_cve_publish_date(chunk: list) -> None:
    assert isinstance(chunk, list), "chunk must be a list"
    assert len(chunk) > 0, "chunk must not be empty"
    first_cve_publish_date = chunk[0].get('cve').get('published', None)
    last_cve_publish_date = chunk[-1].get('cve').get('published', None)

    return first_cve_publish_date, last_cve_publish_date

