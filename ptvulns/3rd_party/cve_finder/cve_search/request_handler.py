import requests
import json
import re
import pyxploitdb
import logging
import time
import config

from cve_search.cve import Cve

def handle_cwe_request(cwe_id):
    """
    Fetch metadata for a given CWE ID from the MITRE CWE API.

    Args:
        cwe_id (str): The CWE ID to fetch metadata for.

    Returns:
        dict: JSON response containing CWE metadata, or None if an error occurs.
    """
    #logging.info(f"Fetching CWE metadata for: {cwe_id}")
    start_time = time.time()

    cwe_id_cleaned = re.sub(r"[^\d]", "", cwe_id)
    if not cwe_id_cleaned:
        logging.warning("Invalid CWE ID after cleaning.")
        return None

    url = f"https://cwe-api.mitre.org/api/v1/cwe/weakness/{cwe_id_cleaned}"
    try:
        response = requests.get(url, timeout=10, verify=True)#config.SSL_VERIFY)
        response.raise_for_status()
        #logging.info(f"CWE metadata for {cwe_id} fetched in {time.time() - start_time:.2f}s")
        return response.json()
    except requests.exceptions.SSLError as e:
        logging.error(f"SSL verification failed for CWE {cwe_id}: {e}. "
                      f"Try running with --no-ssl-verify if you trust the source.")
        return None
    except requests.HTTPError as e:
        if response.status_code == 404:
            logging.warning(f"CWE {cwe_id} not found (404). This may be a category or invalid CWE.")
        else:
            logging.error(f"Failed to fetch CWE {cwe_id}: {e}", exc_info=True)
        return None
    except requests.RequestException as e:
        logging.error(f"Failed to fetch CWE {cwe_id}: {e}", exc_info=True)
        return None

def handle_mitre_request(cpe):
    """
    Fetch CVE data for a given CPE from the MITRE CVE API.

    Args:
        cpe (str): The CPE string to fetch CVE data for.

    Returns:
        list: List of JSON responses containing CVE data, or None if an error occurs.
    """
    logging.info(f"Fetching MITRE CVE data for CPE: {cpe} (This might take a while when dealing with a lot of CVEs)")
    start_time = time.time()

    responses = []

    cve_list = get_cves(cpe)
    total = len(cve_list)
    retries, sleep_time = 5, 3

    for idx, cve in enumerate(cve_list, 1):
        for attempt in range(retries):
            try:
                r = requests.get(f"https://cveawg.mitre.org/api/cve/{cve}", timeout=10)
                r.raise_for_status()
                cve_json = r.json()
                #print(cve_json, end="\n\n\n")
                responses.append(cve_json)
                cve_id = cve_json.get("cveMetadata", {}).get("cveId", "Unknown")
                logging.info(f"Successfully retrieved CVE data for CVE {cve_id} from CVE List.")
                break  # Success, exit retry loop
            except requests.RequestException as e:
                if attempt < retries - 1:
                    logging.warning(f"MITRE request failed for CVE {cve} (attempt {attempt+1}/{retries}): {e}. Retrying in {sleep_time * (2 ** attempt)}s...")
                    time.sleep(sleep_time * (2 ** attempt))
                else:
                    logging.error(f"MITRE request failed for CVE {cve} after {retries} attempts: {e}", exc_info=True)
        if idx % 10 == 0 or idx == total:
            pass#logging.info(f"Fetched {idx}/{total} CVEs from MITRE...")

    #logging.info(f"MITRE data fetched in {time.time() - start_time:.2f}s")
    return responses


def get_cves(cpe):
    """
    Retrieve a list of CVEs from the NVD API based on the provided CPE.

    Args:
        cpe (str): The CPE string to fetch CVEs for.

    Returns:
        list: List of CVE IDs retrieved from NVD.

    Raises:
        Exception: If all attempts to retrieve CVEs fail.
    """
    #logging.info(f"Retrieving list of CVEs from NVD for CPE: {cpe}")
    start_time = time.time()

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
    retries, sleep_time = 8, 5

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                cve_list = [cve["cve"]["id"] for cve in data.get("vulnerabilities", [])]
                logging.info(f"Retrieved {len(cve_list)} CVEs in {time.time() - start_time:.2f}s")
                return cve_list
            elif response.status_code == 503:
                logging.warning(f"NVD API unavailable (503), retry {attempt + 1}/{retries}")
            else:
                logging.warning(f"Unexpected status code {response.status_code}, retry {attempt + 1}/{retries}")
        except requests.RequestException as e:
            logging.error(f"Request exception: {e}", exc_info=True)
        except json.JSONDecodeError:
            logging.error("JSON decode error from NVD", exc_info=True)

        time.sleep(sleep_time * (2 ** attempt))

    raise Exception("All attempts failed to retrieve CVEs from NVD.")

def get_cpe_response(cpe):
    start_time = time.time()

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe}"
    retries, sleep_time = 8, 5

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                cve_list = []
                for cve in data.get("vulnerabilities", []):
                    cve = cve["cve"]
                    source_db = "mitre"
                    cve_id = cve["id"]
                    date_published = cve["published"]
                    # find english description, else take first
                    descriptions = cve.get("descriptions", [])
                    description = next((d["value"] for d in descriptions if d["lang"] == "en"), descriptions[0]["value"] if descriptions else "No description available.")
                    vector = "Unknown"
                    score = "Unknown"
                    metrics = cve.get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                        vector = metrics["cvssMetricV31"][0]["cvssData"]["vectorString"]
                    elif "cvssMetricV30" in metrics:
                        score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                        vector = metrics["cvssMetricV30"][0]["cvssData"]["vectorString"]
                    elif "cvssMetricV2" in metrics:
                        score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
                        vector = metrics["cvssMetricV2"][0]["cvssData"]["vectorString"]

                    cwe_ids = ["Unknown"]
                    cve_list.append(Cve(source_db, cve_id, date_published, description, score, vector, cwe_ids))

                #cve_list = [cve["cve"]["id"] for cve in data.get("vulnerabilities", [])]
                #logging.info(f"Retrieved {len(cve_list)} CVEs in {time.time() - start_time:.2f}s")
                return cve_list
            elif response.status_code == 503:
                logging.warning(f"NVD API unavailable (503), retry {attempt + 1}/{retries}")
            else:
                logging.warning(f"Unexpected status code {response.status_code}, retry {attempt + 1}/{retries}")
        except requests.RequestException as e:
            logging.error(f"Request exception: {e}", exc_info=True)
        except json.JSONDecodeError:
            logging.error("JSON decode error from NVD", exc_info=True)

        time.sleep(sleep_time * (2 ** attempt))

    raise Exception("All attempts failed to retrieve CVEs from NVD.")


def handle_nvd_request(cpe):
    """
    Fetch data from the NVD API for a given CPE.

    Args:
        cpe (str): The CPE string to fetch data for.

    Returns:
        dict: JSON response containing NVD data, or None if an error occurs.
    """
    logging.info(f"Fetching NVD data for CPE: {cpe}")
    start_time = time.time()
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString={cpe}"
    retries, sleep_time = 8, 5

    for attempt in range(retries):
        try:
            response = requests.get(url, timeout=60)
            if response.status_code == 200:
                json_data = response.json()
                logging.info(f"NVD data fetched successfully in {time.time() - start_time:.2f}s")
                return json_data
            elif response.status_code == 503:
                logging.warning(f"NVD API unavailable (503), retry {attempt + 1}/{retries}")
            else:
                logging.warning(f"Unexpected status code {response.status_code}, retry {attempt + 1}/{retries}")
        except requests.RequestException as e:
            logging.error(f"NVD request error: {e}", exc_info=True)
        except json.JSONDecodeError:
            logging.error(f"JSON decoding error for CPE {cpe}", exc_info=True)

        time.sleep(sleep_time * (2 ** attempt))

    logging.error(f"All attempts failed to retrieve NVD data for CPE: {cpe}")
    return None


def handle_osv_request(cpe):
    """
    Fetch OSV data for a given CPE.

    Args:
        cpe (str): The CPE string to fetch OSV data for.

    Returns:
        list: List of JSON responses containing OSV data, or None if an error occurs.
    """
    #logging.info(f"Fetching OSV data for CPE: {cpe}")
    start_time = time.time()

    responses = []
    cve_list = get_cves(cpe)

    for cve in cve_list:
        try:
            r = requests.get(f"https://api.osv.dev/v1/vulns/{cve}", timeout=10)
            r.raise_for_status()
            responses.append(r.json())
        except requests.RequestException as e:
            logging.error(f"OSV request failed for CVE {cve}: {e}", exc_info=True)

    #logging.info(f"OSV data fetched in {time.time() - start_time:.2f}s")
    return responses


def handle_exploit_request(cve):
    """
    Fetch ExploitDB data for a given CVE.

    Args:
        cve (str): The CVE ID to fetch data for.

    Returns:
        dict: JSON response containing ExploitDB data, or None if an error occurs.
    """
    #logging.info(f"Fetching ExploitDB data for CVE: {cve}")
    start_time = time.time()

    try:
        exploit = pyxploitdb.searchCVE(cve)
        if exploit:
            pass#logging.info(f"ExploitDB data fetched successfully for {cve} in {time.time() - start_time:.2f}s")
        else:
            pass#logging.info(f"No ExploitDB available for {cve}")
        return exploit
    except Exception as e:
        logging.error(f"ExploitDB request failed for CVE {cve}: {e}", exc_info=True)
        return None