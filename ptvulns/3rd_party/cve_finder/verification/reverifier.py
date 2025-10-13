import json
import logging
import os
from cve_search import request_handler
from normalizer import normalizer
from analysis import data_processing

def reverify(json_report_path):
    """
    Reverify the CPEs in the given JSON report and save the updated report.

    Args:
        json_report_path (str): Path to the combined JSON report.

    Returns:
        None
    """
    try:
        # Load the existing JSON report
        with open(json_report_path, "r", encoding="utf-8") as json_file:
            report_data = json.load(json_file)

        # Extract the CPE list
        cpe_list = report_data.get("cpe_list", [])
        if not cpe_list:
            logging.warning("No CPEs found in the JSON report.")
            return

        logging.info(f"Starting reverification for {len(cpe_list)} CPE(s).")

        # Initialize a new combined report
        updated_report = {"cpe_list": cpe_list}
        cpes_with_differences = []  # Track CPEs with differences

        for cpe in cpe_list:
            logging.info(f"Re-verifying CPE: {cpe}")
            data_for_analysis = []

            try:
                # Fetch the latest data for the CPE
                nvd_response = request_handler.handle_nvd_request(cpe)
                norm_nvd_response = normalizer.normalize_nvd(nvd_response)

                mitre_response = request_handler.handle_mitre_request(cpe)
                norm_mitre_response = normalizer.normalize_mitre(mitre_response)

                data_for_analysis.extend([norm_nvd_response, norm_mitre_response])

                # Reprocess the data
                analyzed = data_processing.merge(data_for_analysis)
                evaluated = data_processing.evaluate(analyzed)
                unified_output = data_processing.unify(evaluated)

                # Compare the old and new data
                old_data = report_data.get(cpe, {})
                if normalize_for_comparison(old_data) != normalize_for_comparison(unified_output):
                    logging.info(f"Difference detected for CPE: {cpe}")
                    logging.info(f"Old Data: {json.dumps(old_data, indent=4)}")
                    logging.info(f"New Data: {json.dumps(unified_output, indent=4)}")
                    cpes_with_differences.append(cpe)

                # Add the updated data to the new report
                updated_report[cpe] = unified_output

            except Exception as e:
                logging.error(f"Error while re-verifying CPE {cpe}: {e}", exc_info=True)

        # Create the verification_output folder if it doesn't exist
        os.makedirs("verification_output", exist_ok=True)

        # Define the output path for the updated report
        output_filename = os.path.basename(json_report_path).replace(".json", "_verified.json")
        output_path = os.path.join("verification_output", output_filename)

        # Save the updated report
        with open(output_path, "w", encoding="utf-8") as output_file:
            json.dump(updated_report, output_file, indent=4)
        logging.info(f"Updated JSON report successfully written to {output_path}")

        # Log all CPEs with differences at the end
        if cpes_with_differences:
            logging.info("CPEs with differences found during reverification:")
            for cpe in cpes_with_differences:
                logging.info(f" - {cpe}")
        else:
            logging.info("No differences found for any CPE during reverification.")

    except Exception as e:
        logging.error(f"Failed to reverify CPEs: {e}", exc_info=True)

def normalize_for_comparison(obj):
    """
    Recursively sort lists and dicts
    """
    if isinstance(obj, dict):
        return {k: normalize_for_comparison(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        if all(isinstance(i, dict) for i in obj):
            return sorted((normalize_for_comparison(i) for i in obj), key=lambda x: str(x))
        elif all(isinstance(i, str) for i in obj):
            return sorted(obj)
        else:
            return [normalize_for_comparison(i) for i in obj]
    else:
        return obj