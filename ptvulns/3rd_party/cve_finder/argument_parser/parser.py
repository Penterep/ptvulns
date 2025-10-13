import logging
from pprint import pprint
from datetime import datetime
import json
import time
import os
from cve_search import request_handler
from normalizer import normalizer
from analysis import data_processing
from reporting import generate_report
from verification import reverifier

from ptlibs.app_dirs import AppDirs


def parse_find(args):
    """
    Parse the command-line arguments and process the CPEs.

    This function handles the "find" command and generates reports
    based on the provided arguments.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Returns:
        None
    """
    #logging.info("Starting parser execution")
    start_time = time.time()
    #logging.info(args)
    try:
        cpe = []

        if args.file:
            try:
                with open(args.file, mode="r") as file:
                    for line in file:
                        cpe.extend([c.strip() for c in line.split(",") if c.strip()])
                logging.info(f"Loaded {len(cpe)} CPE(s) from file: {args.file}")
            except Exception as e:
                logging.error(f"Failed to read CPEs from file: {args.file} — {e}")
                return
        elif args.cpe:
            cpe = [args.cpe]
            #logging.info(f"Using single CPE from arguments: {args.cpe}")
        else:
            logging.error("No CPE or file provided. Exiting.")
            print("[ERROR] You must provide either a file (-f) or a single CPE (-c).")
            return

        combined_html_reports = []
        combined_json_report = {"cpe_list": cpe}

        for value in cpe:
            logging.info(f"Processing CPE: {value}")
            data_for_analysis = []

            try:
                nvd_response = request_handler.handle_nvd_request(value)
                norm_nvd_response = normalizer.normalize_nvd(nvd_response)
                if args.without_details:
                    norm_mitre_response = request_handler.get_cpe_response(value)
                else:
                    mitre_response = request_handler.handle_mitre_request(value)
                    norm_mitre_response = normalizer.normalize_mitre(mitre_response)

                # osv_response = request_handler.handle_osv_request(value)
                # norm_osv_response = normalizer.normalize_osv(osv_response)
                data_for_analysis.extend([norm_nvd_response, norm_mitre_response])
                #data_for_analysis.extend([norm_nvd_response])

                analyzed = data_processing.merge(data_for_analysis)
                evaluated = data_processing.evaluate(analyzed)
                unified_output = data_processing.unify(evaluated)

                # Add to combined JSON report
                combined_json_report[value] = unified_output

                # Generate HTML report
                """
                html_report = generate_report.generate_html_report(unified_output)
                combined_html_reports.append(
                    f"<h2>Report for CPE: {value}</h2>\n" + html_report
                )
                """

            except Exception as e:
                logging.error(
                    f"Error while processing CPE {value}: {e}", exc_info=True
                )


        # Initialize AppDirs for the tool
        dirs = AppDirs("ptvulns")

        # Timestamp for filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # File paths inside AppDirs data folder
        combined_json_filename = os.path.join(dirs.get_data_dir(), "json_reports", f"combined_report_{timestamp}.json")
        html_report_filename = os.path.join(dirs.get_data_dir(), "html_reports", f"report_{timestamp}.html")
        pdf_report_filename = os.path.join(dirs.get_data_dir(), "pdf_reports", f"report_{timestamp}.pdf")


        try:
            # Save the combined JSON report
            with open(combined_json_filename, "w", encoding="utf-8") as json_file:
                json.dump(combined_json_report, json_file, indent=4)
            #logging.info(
            #    f"Combined JSON report successfully written to {combined_json_filename}"
            #)

            # Combine all HTML reports into a single HTML file
            full_report = (
                "<html><head><title>Combined CVE Report</title></head><body>"
            )
            full_report += "\n<hr>\n".join(combined_html_reports)
            full_report += "</body></html>"

            # Write the HTML report to a file
            with open(html_report_filename, "w", encoding="utf-8") as f:
                f.write(full_report)

            logging.info(
                f"HTML report successfully written to {html_report_filename}"
            )

            # Generate a PDF from the HTML content
            #generate_report.generate_pdf_from_html(full_report, pdf_report_filename)

        except Exception as e:
            logging.error(f"Failed to write report: {e}", exc_info=True)

    finally:
        end_time = time.time()
        elapsed_time = end_time - start_time
        logging.info(f"Total execution time: {elapsed_time:.2f} seconds")

def parse_verification(file_path):
    """
    Handle the verification mode.
    """
    logging.info(f"Starting report verification with file: {file_path}")
    reverifier.reverify(file_path)

