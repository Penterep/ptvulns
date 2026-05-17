import logging
from cve_search.cve import Cve


def get_preferred_cvss_metric(metrics):
    for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metric_name in metrics and metrics[metric_name]:
            primary = next(
                (m for m in metrics[metric_name] if m.get("type") == "Primary"),
                None,
            )
            return primary or metrics[metric_name][0]
    return {}


def format_cvss_impact(cvss_data):
    parts = []
    labels = {
        "attackVector": "Attack vector",
        "attackComplexity": "Attack complexity",
        "privilegesRequired": "Privileges required",
        "userInteraction": "User interaction",
        "scope": "Scope",
        "confidentialityImpact": "Confidentiality impact",
        "integrityImpact": "Integrity impact",
        "availabilityImpact": "Availability impact",
    }
    for key, label in labels.items():
        value = cvss_data.get(key)
        if value not in (None, "Unknown"):
            parts.append(f"{label}: {value}")
    return "; ".join(parts)


def format_affected_versions(configurations):
    affected = []
    fixed_versions = []

    for configuration in configurations:
        for node in configuration.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable"):
                    continue

                criteria = cpe_match.get("criteria", "Unknown CPE")
                constraints = []
                if "versionStartIncluding" in cpe_match:
                    constraints.append(f">= {cpe_match['versionStartIncluding']}")
                if "versionStartExcluding" in cpe_match:
                    constraints.append(f"> {cpe_match['versionStartExcluding']}")
                if "versionEndIncluding" in cpe_match:
                    constraints.append(f"<= {cpe_match['versionEndIncluding']}")
                if "versionEndExcluding" in cpe_match:
                    constraints.append(f"< {cpe_match['versionEndExcluding']}")
                    fixed_versions.append(cpe_match["versionEndExcluding"])

                if constraints:
                    affected.append(f"{criteria} ({', '.join(constraints)})")
                else:
                    affected.append(criteria)

    return "; ".join(affected), ", ".join(dict.fromkeys(fixed_versions))


def format_references(references):
    formatted = []
    for reference in references:
        url = reference.get("url")
        if not url:
            continue
        tags = reference.get("tags", [])
        formatted.append(f"{url} ({', '.join(tags)})" if tags else url)
    return "; ".join(dict.fromkeys(formatted))


def normalize_nvd(response):
    """
    Normalize NVD API response into a list of Cve objects.

    Args:
        response (dict): The raw NVD API response.

    Returns:
        list[Cve]: A list of normalized Cve objects.
    """
    #logging.info("Starting normalization of NVD API response.")
    norm_response = []
    source_db = "nvd"

    if not response:
        logging.warning("Empty NVD response received. Skipping normalization.")
        return norm_response

    for vulnerability in response.get("vulnerabilities", []):
        try:
            cve_data = vulnerability["cve"]
            cve_id = cve_data["id"]
            date_published = cve_data["published"]

            description = vulnerability["cve"]["descriptions"][0]["value"]
            metrics = cve_data.get("metrics", {})
            score = "Unknown"
            vector = "Unknown"
            exploitability_score = "Unknown"
            impact_score = "Unknown"
            cvss_impact = ""

            cvss_metric = get_preferred_cvss_metric(metrics)
            cvss_data = cvss_metric.get("cvssData", {})
            if cvss_data:
                score = cvss_data.get("baseScore", "Unknown")
                vector = cvss_data.get("vectorString", "Unknown")
                exploitability_score = cvss_metric.get("exploitabilityScore", "Unknown")
                impact_score = cvss_metric.get("impactScore", "Unknown")
                cvss_impact = format_cvss_impact(cvss_data)

            weaknesses = cve_data.get("weaknesses", [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-") and val not in cwe_ids:
                        cwe_ids.append(val)

            if not cwe_ids:
                cwe_ids = ["Unknown"]

            affected_versions, fixed_versions = format_affected_versions(
                cve_data.get("configurations", [])
            )
            references = format_references(cve_data.get("references", []))

            cve = Cve(
                source_db,
                cve_id,
                date_published,
                description,
                score,
                vector,
                cwe_ids,
                exploitability_score,
                impact_score,
                cvss_impact,
                affected_versions,
                fixed_versions,
                references,
            )
            norm_response.append(cve)
        except Exception as e:
            logging.error(f"Error normalizing NVD vulnerability: {e}", exc_info=True)

    #logging.info(f"Completed normalization of NVD API response. Total CVEs normalized: {len(norm_response)}.")
    return norm_response


def normalize_mitre(responses):
    """
    Normalize MITRE API response into a list of Cve objects.

    Args:
        responses (list[dict]): The raw MITRE API responses.

    Returns:
        list[Cve]: A list of normalized Cve objects.
    """
    #logging.info("Starting normalization of MITRE API response.")
    norm_response = []
    source_db = "mitre"

    if not responses:
        #logging.warning("Empty MITRE response received. Skipping normalization.")
        return norm_response

    for r in responses:
        try:
            id = r["cveMetadata"]["cveId"]
            date = r["cveMetadata"]["datePublished"]
            description = r["containers"]["cna"]["descriptions"][0]["value"]

            metrics = r["containers"]["cna"].get("metrics", [])
            score = "Unknown"
            vector = "Unknown"

            for metric in metrics:
                if "cvssV3_1" in metric:
                    score = metric["cvssV3_1"]["baseScore"]
                    vector = metric["cvssV3_1"]["vectorString"]
                    break
                elif "cvssV3_0" in metric:
                    score = metric["cvssV3_0"]["baseScore"]
                    vector = metric["cvssV3_0"]["vectorString"]
                    break
                elif "cvssV2" in metric:
                    score = metric["cvssV2"]["baseScore"]
                    vector = metric["cvssV2"]["vectorString"]
                    break

            problem_types = r["containers"]["cna"].get("problemTypes", [])
            if (
                problem_types
                and problem_types[0].get("descriptions")
                and "cweId" in problem_types[0]["descriptions"][0]
            ):
                cwe_id = problem_types[0]["descriptions"][0]["cweId"]
            else:
                cwe_id = "Unknown"

            cve = Cve(source_db, id, date, description, score, vector, cwe_id)
            norm_response.append(cve)
        except Exception as e:
            logging.error(f"Error normalizing MITRE response: {e}", exc_info=True)

    #logging.info(f"Completed normalization of MITRE API response. Total CVEs normalized: {len(norm_response)}.")
    return norm_response


def normalize_osv(responses):
    """
    Normalize OSV API response into a list of Cve objects.

    Args:
        responses (list[dict]): The raw OSV API responses.

    Returns:
        list[Cve]: A list of normalized Cve objects.
    """
    #logging.info("Starting normalization of OSV API response.")
    norm_response = []
    source_db = "osv"

    if not responses:
        logging.warning("Empty OSV response received. Skipping normalization.")
        return norm_response

    for r in responses:
        try:
            if not r:
                continue

            id = r.get("id", "Unknown")
            date = r.get("published", "Unknown")
            description = r.get("details") or r.get("summary", "No description available")

            score = "Unknown"
            vector = "Unknown"
            severity = r.get("severity", [])
            for sev in severity:
                if sev.get("type") == "CVSS_V3":
                    vector = sev.get("score", "Unknown")
                    break

            cwe_id = "Unknown"
            db_specific = r.get("database_specific", {})
            if isinstance(db_specific, dict):
                if (
                    "cwe_ids" in db_specific
                    and isinstance(db_specific["cwe_ids"], list)
                    and db_specific["cwe_ids"]
                ):
                    cwe_id = db_specific["cwe_ids"][0]
            elif "cwe" in r:
                cwe_id = r["cwe"][0]

            cve = Cve(source_db, id, date, description, score, vector, cwe_id)
            norm_response.append(cve)
        except Exception as e:
            logging.error(f"Error normalizing OSV response: {e}", exc_info=True)

    #logging.info(f"Completed normalization of OSV API response. Total CVEs normalized: {len(norm_response)}.")
    return norm_response


def normalize_cwe(response):
    """
    Normalize CWE API response into a dictionary.

    Args:
        response (dict): The raw CWE API response.

    Returns:
        dict: A dictionary containing normalized CWE data.
    """
    #logging.info("Starting normalization of CWE API response.")
    norm_response = {}

    if response is None:
        logging.error("CWE normalization failed: response is None (likely 404 or invalid CWE).")
        return norm_response

    try:
        weaknesses = response.get("Weaknesses")
        if not weaknesses or not isinstance(weaknesses, list) or len(weaknesses) == 0:
            logging.warning("No weaknesses found in CWE response (possibly a category ID).")
            return norm_response

        weakness = weaknesses[0]
        cwe_id = weakness.get("ID", "Unknown")
        cwe_name = weakness.get("Name", "Unknown")
        cwe_desc = weakness.get("Description", "No description available")

        norm_response[cwe_id] = {
            "name": cwe_name,
            "description": cwe_desc,
            "source_db": "cwe",
        }

        #logging.info(f"Successfully normalized CWE ID: {cwe_id}.")
    except Exception as e:
        logging.error(f"CWE normalization failed: {e}", exc_info=True)

    return norm_response


def normalize_exploit(response):
    """
    Normalize ExploitDB API response into a dictionary.

    Args:
        response (list): The raw ExploitDB API response.

    Returns:
        dict: A dictionary containing normalized exploit data.
    """
    #logging.info("Starting normalization of ExploitDB API response.")
    if not response:
        logging.warning("Empty ExploitDB response received. Skipping normalization.")
        return {}

    try:
        exploit = response[0]
        norm_response = {
            "id": exploit.id,
            "description": exploit.description,
            "link": exploit.link,
            "source_db": "exploit_db",
        }
        #logging.info(f"Successfully normalized Exploit ID: {exploit.id}.")
        return norm_response
    except Exception as e:
        logging.error(f"Exploit normalization failed: {e}", exc_info=True)
        return {}
