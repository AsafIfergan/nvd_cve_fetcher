import argparse
from collections import Counter

from utils.analysis_utils import get_analysis
from utils.general_utils import print_divider, load_jsons_from_directory, calculate_numeric_array_average


def get_jsons_analysis(path_to_jsons):

    score_averages = []
    all_severities = Counter()
    affected_packages = Counter()

    json_loader = load_jsons_from_directory(path_to_jsons) # generator function
    for loaded_json in json_loader:
        average_base_score, current_severities, current_affected_packages = get_analysis(loaded_json)
        all_severities = all_severities + current_severities
        affected_packages = affected_packages + current_affected_packages
        score_averages.append(average_base_score)

    total_average = calculate_numeric_array_average(score_averages)
    top_5_affected_packages = affected_packages.most_common(5)
    return total_average, all_severities, top_5_affected_packages


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-directory", default=None, required=True, type=str)
    args = parser.parse_args()
    return args

def main():

    args = get_args()
    print_divider()
    print("Starting analysis...")
    total_average, severities, top_5_affected_packages = get_jsons_analysis(args.output_directory)
    print_divider()
    print(f"Base score average for analysed vulnerabilities: {total_average}")
    print_divider()
    print("Severity breakdown analysed vulnerabilities:")
    for severity_level, count in severities.items():
        print(f"{severity_level}: {count}")
    print_divider()
    print("Top 5 affected packages in analysed vulnerabilities:\n")
    for package_name, count in top_5_affected_packages:
        print(f"{package_name}: {count}")

if __name__ == '__main__':
    main()