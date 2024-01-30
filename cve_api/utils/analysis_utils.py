from collections import Counter

from .general_utils import is_numeric, calculate_numeric_array_average

def iterate_cves(loaded_json):
    for cve_object in loaded_json:
        cve_info_dict = cve_object.get('cve', None)
        if cve_info_dict:
            yield cve_info_dict


def get_analysis(json, metrics_to_get=('baseScore', 'baseSeverity')):

    affected_packages = Counter()
    base_scores = []
    base_severities = Counter()

    cves_generator = iterate_cves(json)

    for cev_data_dict in cves_generator:
        current_affected_packages_counter = count_affected_packages(cev_data_dict)
        affected_packages = affected_packages + current_affected_packages_counter
        primary_metrics = get_metrics_object(
            cev_data_dict)  # primary_metrics include the NVD and CNA. more here in the documentation
        if not primary_metrics:
            continue

        fetched_metrics = get_metrics_from_cvss(primary_metrics, metrics_to_get)
        base_severity = fetched_metrics.get('baseSeverity', None)
        base_score = fetched_metrics.get('baseScore', None)

        if base_severity:
            base_severities[base_severity.lower()] += 1
        base_score = is_numeric(base_score)
        if base_score is not None:
            base_scores.append(base_score)

    average_base_score = calculate_numeric_array_average(base_scores)
    return average_base_score, base_severities, affected_packages


def get_metrics_from_cvss(metrics_object, metrics_to_get: list):
    cvss_data = metrics_object.get('cvssData', None)
    if cvss_data is None:
        return None, None

    fetched_metrics = {}
    for metric in metrics_to_get:
        fetched_metrics[metric] = cvss_data.get(metric, None)

    return fetched_metrics


def count_affected_packages(cev_data_dict):
    package_counts = Counter()

    configurations = cev_data_dict.get('configurations', [])
    for configuration in configurations:
        for node in configuration.get('nodes', []):
            for cpe_match in node.get('cpeMatch', []):
                if cpe_match.get('vulnerable', False):
                    package_name = extract_package_name(cpe_match['criteria'])
                    package_counts[package_name] += 1

    return package_counts


def extract_package_name(
        cpe_string: str):  # wfn:[part="a",vendor="microsoft",product="internet_explorer", version="8\.0\.6001",update="beta"]
    try:
        parts = cpe_string.split(':')
        return f"{parts[3]}_{parts[4]}"
    except Exception:
        return "unknown"


def get_metrics_object(cve_data_dict: dict) -> dict:
    metrics = cve_data_dict.get('metrics', None)
    if not metrics:
        # we can add this print statement to the end of each if statement above, but perhaps it's not necessary as cve's without metrics are not interesting to us
        # print(f'No metrics found for CVE with id: {cve_data_dict.get("id", None)}')
        return

    v20_metrics = metrics.get('cvssMetricV2', None)
    if v20_metrics:
        return return_primary_metric(v20_metrics)
    v30_metrics = metrics.get('cvssMetricV30', None)
    if v30_metrics:
        return return_primary_metric(v30_metrics)
    v31_metrics = metrics.get('cvssMetricV31', None)
    if v31_metrics:
        return return_primary_metric(v31_metrics)

    else:
        # this print statement is necessary because we want to know if there are any metrics versions that we're not handling
        print(f'Did not find known metrics for CVE: {cve_data_dict.get("id", None)}')


def return_primary_metric(metrics_list: list) -> dict:
    for metrics in metrics_list:
        if metrics.get('type', None) == 'Primary':
            return metrics
