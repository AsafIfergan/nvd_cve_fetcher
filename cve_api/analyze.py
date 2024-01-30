import argparse
from collections import Counter

from utils.analysis_utils import get_analysis
from utils.general_utils import print_divider, load_jsons_from_directory, calculate_numeric_array_average


def get_jsons_analysis(path_to_jsons, n_top_affected_packages: int = 5):
    score_averages = []
    all_severities = Counter()
    affected_packages = Counter()

    json_loader = load_jsons_from_directory(path_to_jsons)  # generator function
    for loaded_json in json_loader:
        average_base_score, current_severities, current_affected_packages = get_analysis(loaded_json)
        all_severities = all_severities + current_severities
        affected_packages = affected_packages + current_affected_packages
        score_averages.append(average_base_score)

    total_average = calculate_numeric_array_average(score_averages)
    top_affected_packages = affected_packages.most_common(n_top_affected_packages)
    return total_average, all_severities, top_affected_packages


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", default=None, required=True, type=str)
    args = parser.parse_args()
    return args


def print_analysis_results(total_average, severities, top_affected_packages, n_top_affected_packages):

    validate_results(total_average, severities, top_affected_packages)
    print_divider()
    assert total_average
    print(f"Base score average for analysed vulnerabilities: {total_average}")
    print_divider()
    print("Severity breakdown for analysed vulnerabilities:")
    if isinstance(severities, dict):
        for severity_level, count in severities.items():
            print(f"{severity_level}: {count}")
    else:
        print("No severity data found")
    print_divider()
    print(f"Top {n_top_affected_packages} affected packages in analysed vulnerabilities:\n")
    for package_name, count in top_affected_packages:
        print(f"{package_name}: {count}")


def validate_results(total_average, severities, top_affected_packages):
    assert isinstance(total_average, (int, float)), "total_average must be a numeric value"
    assert isinstance(severities, dict), "severities must be a dictionary"
    assert isinstance(top_affected_packages, list), "top_affected_packages must be a list"
    assert all(isinstance(item, tuple) for item in top_affected_packages), "top_affected_packages must be a list of tuples"

def main():
    args = get_args()
    n_top_affected_packages = 5
    output_directory = args.output_directory
    total_average, severities, top_affected_packages = get_jsons_analysis(output_directory,
                                                                          n_top_affected_packages=n_top_affected_packages)
    print_analysis_results(total_average, severities, top_affected_packages, n_top_affected_packages)


if __name__ == '__main__':
    main()
