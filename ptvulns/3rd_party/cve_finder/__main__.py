import argparse
import logging
import os

import argument_parser.parser
import config

from ptlibs.app_dirs import AppDirs
from ptlibs.ptprinthelper import terminal_width, len_string_without_colors

def main():
    """
    Main entry point for the CVE Finder script.

    This function sets up logging, parses command-line arguments, and calls the appropriate
    function based on the arguments provided. It supports finding specific CPEs and processing them.

    - Creates a `logs` directory if it doesn't already exist.
    - Configures logging to write logs to `logs/cve_tool.log`.
    - Parses command-line arguments to determine the operation to perform.

    Command-line arguments:
        - `find`: Find specific CPEs and process them.
        - `-c` or `--cpe`: Specify a specific CPE string to process.
        - `-f` or `--file`: Specify a file containing CPEs to process.
        - `--verification`: Run verification process (requires `--file`).
        - `--help`: Show help message.
        - '--no-ssl-verify': Disables SSL certificate verification for API calls.

    Returns:
        None
    """

    dirs = AppDirs("ptvulns")
    # Subdirectories to create inside data/
    #subdirs = ["logs", "json_reports", "html_reports", "pdf_reports"]

    for sub in ["json_reports"]:
        path = os.path.join(dirs.get_data_dir(), sub)
        os.makedirs(path, exist_ok=True)

    class InfoOnlyFilter(logging.Filter):
        def filter(self, record):
            return record.levelno == logging.INFO

    # Configure logging
    logging.basicConfig(
        #filename="logs/cve_tool.log",
        level=logging.INFO,
        format=f"%(message)s     ",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logging.getLogger().addFilter(InfoOnlyFilter())


    #logging.info("CVE Finder started.")
    parser = argparse.ArgumentParser(prog="cve-search")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f",
        "--file",
        help="File containing CPEs (comma-separated or one per line)",
    )
    group.add_argument("-c", "--cpe", help="Single CPE string")
    parser.add_argument(
        "--verification",
        action="store_true",
        help="Run verification process (requires --file)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification for some requests.",
    )

    parser.add_argument("-wd", "--without-details", action="store_true")
    args = parser.parse_args()
    #logging.info(args)
    #logging.info(f"Parsed arguments: {args}")

    # Set SSL verification flag in config
    if args.no_ssl_verify:
        config.SSL_VERIFY = False
        logging.warning("SSL certificate verification is DISABLED for all API requests.")

    # Verification mode
    if args.verification:
        #logging.info("Verification mode selected.")
        if not args.file:
            logging.error("--verification requires --file")
            parser.print_help()
            return
        logging.info(f"Running verification on file: {args.file}")
        # Call verification logic
        argument_parser.parser.parse_verification(args.file)
        logging.info("Verification process completed.")
    else:
        # Regular data aggeration mode
        #logging.info("Normal find mode selected.")
        if args.cpe:
            pass#logging.info(f"Processing single CPE: {args.cpe}")
        elif args.file:
            logging.info(f"Processing CPEs from file: {args.file}")
        argument_parser.parser.parse_find(args)
        logging.info("Find process completed.")

    logging.shutdown()


if __name__ == "__main__":
    main()