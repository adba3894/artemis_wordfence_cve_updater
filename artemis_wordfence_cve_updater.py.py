import json
import requests
import logging
from packaging import version

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

vulnerabilities_url = (
    "https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production"
)
artemis_file_name = input("Enter the file name for Artemis data (e.g., data.json): ")
vulnerability_list = []


def fetch_wordfence_vulnerabilities(url: str) -> [dict[str, any]]:
    """Fetching vulnerabilities data from Wordfence."""
    response = requests.get(url)
    if response.status_code == 200:
        logging.info("Successfully fetched vulnerabilities data from Wordfence.")
        return response.json()
    else:
        logging.error(f"Failed to fetch vulnerabilities data. Error: {e}")
        return {}


def load_artemis_data(artemis_file_name: str) -> dict[str, any]:
    """Load Artemis data from a local JSON file."""
    try:
        with open(artemis_file_name, "r") as artemis_file:
            logging.info(f"Successfully loaded data from {artemis_file_name}.")
            return json.load(artemis_file)
    except FileNotFoundError:
        logging.error(f"File {artemis_file_name} not found.")
        return {}
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON from {artemis_file_name}: {e}")
        return {}


def is_version_vulnerable(
    target_version: str, version_intervals: dict[str, dict[str, any]]
) -> bool:
    target_version = version.parse(target_version)

    for interval, details in version_intervals.items():
        from_version = details.get("from_version")
        to_version = details.get("to_version")

        if from_version == "*":
            from_version = version.parse("0.0.0")
        else:
            from_version = version.parse(from_version)

        if to_version == "*":
            to_version = version.parse("9999.9999.9999")
        else:
            to_version = version.parse(to_version)

        from_inclusive = details.get("from_inclusive", True)
        to_inclusive = details.get("to_inclusive", True)

        if (
            (from_inclusive and target_version >= from_version)
            or (not from_inclusive and target_version > from_version)
        ) and (
            (to_inclusive and target_version <= to_version)
            or (not to_inclusive and target_version < to_version)
        ):
            return True

    return False


def add_cves_to_artemis_report(
    artemis_data: dict[str, any], vulnerabilities_data: dict[str, any]
) -> None:
    """Adding CVE numbers to Artemis report."""
    for target, target_data in artemis_data.get("messages", {}).items():
        logging.info(f"Processing target: {target}")

        reports = target_data.get("reports", [])

        for report in reports:
            artemis_additional_data = report.get("additional_data", {})
            artemis_type = artemis_additional_data.get("type")
            artemis_slug = artemis_additional_data.get("slug")
            artemis_version = artemis_additional_data.get("version")

            cves_to_artemis_file = []

            for vulnerability in vulnerability_list:
                if (
                    artemis_slug == vulnerability.get("slug")
                    and artemis_type == "plugin"
                    and is_version_vulnerable(
                        artemis_version, vulnerability.get("affected_versions")
                    )
                ):

                    cve_entry = {
                        vulnerability.get("cve", "N/A"): {
                            "cvss": vulnerability.get("cvss", "N/A"),
                            "remediation": vulnerability.get("remediation", "N/A"),
                            "affected_versions": vulnerability.get(
                                "affected_versions", {}
                            ),
                            "patched_versions": vulnerability.get(
                                "patched_versions", []
                            ),
                            "patched": vulnerability.get("patched", False),
                        }
                    }

                    cves_to_artemis_file.append(cve_entry)

            if cves_to_artemis_file:
                artemis_additional_data["cves"] = cves_to_artemis_file
                report["additional_data"] = artemis_additional_data


def collect_vulnerability_data(
    artemis_data: dict[str, any], vulnerabilities_data: dict[str, any]
) -> None:
    """Collecting vulnerability data from Wordfence."""
    for vulnerability_id, vulnerability in vulnerabilities_data.items():
        for software in vulnerability.get("software", []):

            vulnerability_details = {
                "id": vulnerability.get("id", "N/A"),
                "cve": vulnerability.get("cve", "N/A"),
                "cvss": vulnerability.get("cvss", {}).get("score", "N/A"),
                "affected_versions": software.get("affected_versions", {}),
                "slug": software.get("slug"),
                "remediation": software.get("remediation"),
                "from_version": software.get("affected_versions", {}).get(
                    "from_version"
                ),
                "from_inclusive": software.get("affected_versions", {}).get(
                    "from_inclusive"
                ),
                "to_version": software.get("affected_versions", {}).get("to_version"),
                "to_inclusive": software.get("affected_versions", {}).get(
                    "to_inclusive"
                ),
                "patched": software.get("patched", False),
                "patched_versions": software.get("patched_versions", []),
            }

            vulnerability_list.append(vulnerability_details)


vulnerabilities_data = fetch_wordfence_vulnerabilities(vulnerabilities_url)
artemis_data = load_artemis_data(artemis_file_name)

collect_vulnerability_data(artemis_data, vulnerabilities_data)
add_cves_to_artemis_report(artemis_data, vulnerabilities_data)

with open(artemis_file_name, "w") as artemis_file:
    json.dump(artemis_data, artemis_file, indent=4)
