from pprint import pprint
from cve_search import request_handler
from normalizer import normalizer
import time
import logging


def normalize_desc(desc):
    return " ".join(desc.split()).strip().lower()

def merge(cve_data):
    """
    Merge CVE data from multiple sources into a unified structure.

    This function groups all the data by CVE ID and organizes it into a dictionary
    where each CVE ID contains its associated fields and values from different sources.

    Args:
        cve_data (list): A list of CVE data from multiple sources.

    Returns:
        dict: A dictionary containing merged CVE data grouped by CVE ID.
    """
    #logging.info("Starting merging function")
    start_time = time.time()

    analyzed = {}
    try:
        for source_list in cve_data:
            for entry in source_list:
                cve_id = entry.id
                if cve_id not in analyzed:
                    analyzed[cve_id] = {}

                entry_dict = entry.__dict__

                for field, value in entry_dict.items():
                    if field not in analyzed[cve_id]:
                        analyzed[cve_id][field] = []

                    if field == "cwe_id" and isinstance(value, list):
                        for cwe in value:
                            analyzed[cve_id][field].append((entry.source_db, cwe))
                    else:
                        analyzed[cve_id][field].append((entry.source_db, value))

        duration = time.time() - start_time
        #logging.info(f"Merging completed successfully in {duration:.2f}s")

    except Exception as e:
        duration = time.time() - start_time
        logging.error(f"Merging failed after {duration:.2f}s: {e}", exc_info=True)
    return analyzed


def evaluate(analyzed_data) -> dict:
    """
    Evaluate merged CVE data to verify and select the most reliable information.

    This function processes the merged data to verify fields, calculate averages,
    and select the most reliable values based on the number of sources.

    Args:
        analyzed_data (dict): The merged CVE data grouped by CVE ID.

    Returns:
        dict: A dictionary containing evaluated CVE data with verified fields.
    """
    evaluated = {}
    #logging.info("Starting evaluation function")
    start_time = time.time()

    try:
        for cve_id, fields in analyzed_data.items():
            evaluated[cve_id] = {"id": cve_id}

            for field, sources in fields.items():
                # Skip these fields, no need to do anything with them
                if field in ["source_db", "id"]:
                    continue

                # Filter out 'Unknown' values
                valid_values = [(src, val) for src, val in sources if val != "Unknown"]

                # Count different values
                value_counts = {}
                for src, val in valid_values:
                    if val not in value_counts:
                        value_counts[val] = []
                    value_counts[val].append(src)

                # Verification
                verified_value = None
                verified_by = []
                for val, srcs in value_counts.items():
                    if len(srcs) >= 2:
                        verified_value = val
                        verified_by = srcs
                        break

                # Handle scoring, calculate average score
                if field == "score":
                    scores = {src: val for src, val in valid_values}
                    avg_score = (
                        round(
                            sum(float(val) for val in scores.values()) / len(scores), 2
                        )
                        if scores
                        else None
                    )
                    evaluated[cve_id][field] = {
                        "values": scores,
                        "average": avg_score,
                        "verified": verified_value is not None,
                        "verified_by": verified_by,
                    }

                elif field == "vector":
                    vectors = {src: val for src, val in valid_values}
                    evaluated[cve_id][field] = {
                        "values": vectors,
                        "verified": verified_value is not None,
                        "verified_by": verified_by,
                    }

                # Longest available description will be chosen
                elif field == "desc":

                    longest_desc = ""
                    longest_sources = []

                    for src, val in valid_values:
                        if len(val) > len(longest_desc):
                            longest_desc = val

                    for src, val in valid_values:
                        if normalize_desc(val) == normalize_desc(longest_desc):
                            longest_sources.append(src)

                    verified = len(longest_sources) >= 2

                    evaluated[cve_id][field] = {
                        "values": dict(sources),
                        "selected": longest_desc,
                        "verified": verified,
                        "verified_by": longest_sources if verified else [],
                    }

                # CWEs
                elif field == "cwe_id":
                    cwe_value_sources = {}

                    for src, val in valid_values:
                        # Values should always be a list - one CWE or multiple
                        values = val if isinstance(val, list) else [val]
                        for v in values:
                            if v not in cwe_value_sources:
                                cwe_value_sources[v] = []
                            cwe_value_sources[v].append(src)

                    selected = []
                    for val, srcs in cwe_value_sources.items():
                        verified = len(srcs) >= 2
                        selected.append(
                            {
                                "id": val,
                                "verified": verified,
                                "verified_by": srcs if verified else [],
                            }
                        )

                    evaluated[cve_id][field] = selected

                # Default case, shouldn't be used in current state
                else:
                    selected_value = (
                        verified_value
                        if verified_value is not None
                        else (valid_values[0][1] if valid_values else "Unknown")
                    )
                    evaluated[cve_id][field] = {
                        "values": dict(sources),
                        "selected": selected_value,
                        "verified": verified_value is not None,
                        "verified_by": verified_by,
                    }

        duration = time.time() - start_time
        #logging.info(f"Evaluation completed successfully in {duration:.2f}s")

    except Exception as e:
        duration = time.time() - start_time
        logging.error(f"Evaluation failed after {duration:.2f}s: {e}", exc_info=True)

    return evaluated


def unify(evaluated_data):
    """
    Unify evaluated CVE data into a final structure for reporting.

    This function processes the evaluated data to create a unified structure
    that includes metadata, exploit information, and sources.

    Args:
        evaluated_data (dict): The evaluated CVE data grouped by CVE ID.

    Returns:
        list: A list of unified CVE entries ready for reporting.
    """
    #logging.info("Starting unification function")
    start_time = time.time()

    unified_list = []

    try:
        for cve_id, fields in evaluated_data.items():
            unified_entry = {"id": cve_id}
            cwe_metadata = []
            cwe_ids_seen = set()
            sources = set()

            for field, details in fields.items():
                if field == "score":
                    unified_entry[field] = {
                        "values": details.get("values", {}),
                        "average": details.get("average"),
                        "verified": details.get("verified", False),
                        "verified_by": details.get("verified_by", []),
                    }
                    sources.update(details.get("values", {}).keys())

                elif field == "vector":
                    unified_entry[field] = {
                        "values": details.get("values", {}),
                        "verified": details.get("verified", False),
                        "verified_by": details.get("verified_by", []),
                    }
                    sources.update(details.get("values", {}).keys())

                elif field == "cwe_id":
                    unified_entry[field] = []
                    for cwe in details:
                        cwe_id = cwe["id"]
                        if cwe_id not in cwe_ids_seen:
                            cwe_ids_seen.add(cwe_id)
                            unified_entry[field].append(
                                {
                                    "id": cwe_id,
                                    "verified": cwe.get("verified", False),
                                    "verified_by": cwe.get("verified_by", []),
                                }
                            )
                            """
                            try:
                                cwe_response = request_handler.handle_cwe_request(cwe_id)
                                cwe_info = normalizer.normalize_cwe(cwe_response)
                                cwe_metadata.extend(cwe_info.values())
                                sources.add("cwe-database")
                                logging.debug(f"CWE metadata fetched for {cwe_id}")
                            except Exception as e:
                                logging.error(
                                    f"CWE normalization failed for {cwe_id}: {e}",
                                    exc_info=True,
                                )
                            """

                        sources.update(cwe.get("verified_by", []))

                elif field in ("desc", "date_published"):
                    unified_entry[field] = {
                        "selected": details.get("selected", "Unknown"),
                        "verified": details.get("verified", False),
                        "verified_by": details.get("verified_by", []),
                    }
                    sources.update(details.get("verified_by", []))

                else:
                    unified_entry[field] = {
                        "selected": details,
                        "verified": False,
                        "verified_by": [],
                    }

            if cwe_metadata:
                unified_entry["cwe_metadata"] = cwe_metadata

            """
            # Get exploit information
            try:
                exploit_response = request_handler.handle_exploit_request(cve_id)
                normalized_exploit = normalizer.normalize_exploit(exploit_response)
                if normalized_exploit:
                    unified_entry["exploit"] = normalized_exploit
                    sources.add("exploit-db")
                    logging.debug(f"Exploit data fetched for {cve_id}")

            except Exception as e:
                logging.error(
                    f"Exploit normalization failed for {cve_id}: {e}", exc_info=True
                )
                unified_entry["exploit"] = {}
            """
            unified_entry["sources"] = list(sources)
            unified_list.append(unified_entry)

        duration = time.time() - start_time
        #logging.info(f"Unification completed successfully in {duration:.2f}s")

    except Exception as e:
        duration = time.time() - start_time
        logging.error(f"Unification failed after {duration:.2f}s: {e}", exc_info=True)
        raise

    return unified_list
