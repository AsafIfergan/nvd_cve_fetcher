import json
import os
from typing import Union


def print_divider():
    print("\n", "=" * 30, "\n")


def log_message(verbose, message):
    """Log a message if verbose mode is enabled."""
    if verbose and message:
        print(message)


def create_directory_with_parents(directory_path, exist_ok=True):
    os.makedirs(directory_path, exist_ok=exist_ok)


def save_json(filepath: str, cve_list: list, verbose=False) -> None:
    """ saves a list of CVEs to a json file.
    Args:
        filepath (str): path to the file where the CVEs will be saved
        cve_list (list): list of CVEs to be saved"""

    try:
        with open(filepath, 'w') as f:
            json.dump(cve_list, f, indent=4)
            print_divider()
            log_message(verbose, f"Successfully saved results to {filepath}")
    except Exception as e:
        log_message(verbose, f"Failed to save results to {filepath}")
        print(e)


def yield_list_chunks(all_cves: list, chunk_size: int = 50) -> list:
    """ a generator function that yields a chunk of a list of elements.
    Args:
        all_cves (list): list of elements to be divided into chunks
        chunk_size (int, optional): size of each chunk. Defaults to 50 as required"""
    list_of_chunks = []
    for i in range(0, len(all_cves),
                   chunk_size):  # range takes a start, stop, and step as args and not kwargs. if you don't specify a start, it defaults to 0
        list_of_chunks.append(all_cves[i:i + chunk_size])
        yield all_cves[i:i + chunk_size]


def load_json(file_path: str):
    with open(file_path, 'r') as f:
        return json.load(f)


def load_jsons_from_directory(directory_path: str):
    for root, dirs, files in os.walk(directory_path,
                                     topdown=False):  # os.walk allows to find jsons in nested directories
        for file in files:
            if file.endswith(".json"):
                filepath = os.path.join(root, file)
                yield load_json(filepath)


def is_numeric(item: Union[int, float, str]):
    try:
        item = float(item)
        return item
    except ValueError:
        return False


def calculate_numeric_array_average(array: Union[list, tuple], clean_array=True):
    """Calculate the average of a list or tuple of numeric values."""
    if clean_array:
        array = [item for item in array if is_numeric(item)]
    assert all(isinstance(item, (int, float)) for item in array), "All items in the array must be numeric"
    if not array:
        return 0
    return sum(array) / len(array)
