#!/usr/bin/python3
"""
Copyright (c) 2025 Penterep Security s.r.o.

ptvulns is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ptvulns is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with ptvulns.  If not, see <https://www.gnu.org/licenses/>.
"""

import importlib
import os
import threading
import subprocess
import shutil
import itertools
import time
import json
import hashlib
import pty
import select
import subprocess
import sys; sys.path.append(__file__.rsplit("/", 1)[0])

from types import ModuleType
from urllib.parse import urlparse, urlunparse
from ptlibs import ptjsonlib, ptmisclib, ptnethelper
from ptlibs.ptprinthelper import ptprint, print_banner, help_print, get_colored_text
from ptlibs.threads import ptthreads, printlock
from ptlibs.http.http_client import HttpClient
from ptlibs.app_dirs import AppDirs

import argparse

from _version import __version__

class PtVulns:
    def __init__(self, args):
        self.args        = args
        self.ptjsonlib   = ptjsonlib.PtJsonLib()
        self.http_client = HttpClient(args=self.args, ptjsonlib=self.ptjsonlib)
        self.app_dirs    = AppDirs("ptvulns")

        self.current_dir = os.path.dirname(os.path.abspath(__file__))

    def run(self) -> None:
        """Main method"""

        cpe = self.args.search

        self.clear_folder(self.app_dirs.get_path("json_reports"))

        if self.args.update:
            # call string to automat that creates cpe and return the cpe string
            cpe_search_path = os.path.join(self.current_dir, '3rd_party', 'cpe_search', 'cpe_search.py')
            ptprint(f"Updating cpe-db file:", "TITLE", (not self.args.json), colortext=True)
            result = self.call_external_script([sys.executable, cpe_search_path, "--update", "--verbose"])
            return

        if not self.is_cpe(cpe):
            # call string to automat that creates cpe and return the cpe string
            cpe_search_path = os.path.join(self.current_dir, '3rd_party', 'cpe_search', 'cpe_search.py')
            ptprint(f"Running CPE search:", "TITLE", (not self.args.json) and self.args.verbose, colortext=True)

            cpe_args = [sys.executable, cpe_search_path, "-q", self.args.search, "--verbose"]
            result = self.call_external_script(cpe_args)

            cpe = self.parse_cpe_from_result(result)

        ptprint(f"Running CVE Finder:", "TITLE", not self.args.json and self.args.verbose, colortext=True, newline_above=True, clear_to_eol=True)
        cve_search_path = os.path.join(self.current_dir, '3rd_party', 'cve_finder', '__main__.py')
        cve_args = [sys.executable, cve_search_path, "--cpe", cpe, "--no-ssl-verify"]
        if self.args.without_details:
            cve_args.append("-wd")

        result = self.call_external_script(cve_args)

        if not result or "Retrieved 0 CVEs".lower() in result.lower():
            self.ptjsonlib.end_ok("0 CVEs found", self.args.json, bullet_type=None)

        path = self.get_latest_combined_report_path()

        ptprint(f"CVE report:", "TITLE", (not self.args.json) and self.args.verbose, colortext=True, newline_above=True, clear_to_eol=True)
        self.print_cve_report(path)


        self.ptjsonlib.set_status("finished")
        ptprint(self.ptjsonlib.get_result_json(), "", self.args.json)

    def clear_folder(self, folder_path: str):
        """
        Deletes all files and subfolders in the specified folder,
        but keeps the folder itself.
        """
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isdir(item_path):
                    shutil.rmtree(item_path)  # remove subfolder
                else:
                    os.remove(item_path)      # remove file

    def print_cve_report(self, file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        cpe_list = data.get("cpe_list", [])

        if self.args.group_vulns:
            grouped_result: str = ""

        for cpe in cpe_list:
            entries = data.get(cpe, [])
            #if entries:
            #    self.ptjsonlib.add_vulnerability("PTV-WEB-SW-KNOWNVULN")
            for entry in sorted(entries, key=lambda e: e["score"]["average"], reverse=True):
                cve_id = entry["id"]["selected"]
                date = entry["date_published"]["selected"].split("T")[0]
                score = entry["score"]["average"]
                exploitability_score = entry["exploitability_score"]["selected"]["selected"]
                desc = entry["desc"]["selected"]
                #vector = (lambda d: {next(iter(d)): d[next(iter(d))]} if d else None)(entry["vector"].get("values", {}))
                vector = next(iter(entry["vector"].get("values", {}).values()), None)
                cwe = entry["cwe_id"][0].get("id") if entry.get("cwe_id") else None
                severity = "vulnSeverity" + self.get_severity(score)

                ptprint(get_colored_text(f"CVE: {cve_id}", "TITLE"), "TEXT", not self.args.json, indent=0)
                ptprint(f"Published: {date}", "TEXT", not self.args.json, indent=0)

                #ptprint(f"Exploitability Score: {exploitability_score}", "TEXT", not self.args.json, indent=0)
                #ptprint(f"CVSS Score: {score}", "TEXT", not self.args.json, indent=0)

                ptprint(f"Exploitability Score: {get_colored_text(exploitability_score, self._get_color_by_score(exploitability_score))}", "TEXT", not self.args.json, indent=0)
                ptprint(f"CVSS Score: {get_colored_text(score, self._get_color_by_score(score))}", "TEXT", not self.args.json, indent=0)

                ptprint(f"CVSS String: {vector}", "TEXT", not self.args.json, indent=0)
                ptprint(f"Description: {desc}\n", "TEXT", not self.args.json, indent=0)

                #node = self.ptjsonlib.create_node_object(node_type="cve", properties={"cve": cve_id, "published": date, "score": score, "description": desc})
                if self.args.group_vulns:
                    grouped_result += f"**{cve_id}**, CVSS Score: **{score}**, CVSS Vector: **{vector}**\n\n{desc.lstrip()}\n\n"
                else:
                    self.ptjsonlib.add_vulnerability(vuln_code=cve_id, name=cve_id, description=desc, causes=None, displays=None, impacts=None, recommendation=None, location=self.args.search, scoring=vector or score, severity=severity, cve=cve_id, cwe=cwe)
                #self.ptjsonlib.add_node(node)

            if entries:
                ptprint(f"Retrieved {len(entries)} CVEs for CPE: {cpe}", "INFO", (not self.args.json) and self.args.verbose, colortext=True, newline_above=True, clear_to_eol=True)

        if self.args.group_vulns:
            self.ptjsonlib.add_vulnerability(vuln_code="PTV-WEB-SW-KNOWNVULN", displays=grouped_result)

        #os.remove(file_path) # remove the file

    def _get_color_by_score(self, score):
        if score >= 8:
            return "VULN"
        elif score > 6:
            return "TITLE"
        else:
            return "TEXT"

    def get_severity(self, score):
        """
        Determine the severity level based on the CVSS score.
        """
        try:
            score = float(score)
            if score >= 9.0:
                return "Critical"
            elif score >= 7.0:
                return "High"
            elif score >= 4.0:
                return "Medium"
            elif score > 0.0:
                return "Low"
            else:
                return "None"
        except Exception:
            return "Unknown"


    def get_latest_combined_report_path(self):
        # list all files starting with "combined_report_"
        reports_folder = self.app_dirs.get_path("json_reports")
        files = [f for f in os.listdir(reports_folder) if f.startswith("combined_report_")]

        if not files:
            raise FileNotFoundError("No combined_report_ files found in json_reports folder.")

        # select the newest file based on the date-time part
        newest_file = max(files, key=lambda f: f[len("combined_report_"):])
        path = os.path.join(reports_folder, newest_file)

        return path

    def parse_cpe_from_result(self, result: str):
        if result:
            if "could not find software for query:" in result.lower():
                self.ptjsonlib.end_error(f"No CPE found for query: {self.args.search}", condition=self.args.json)
            cpe = result.strip().split("\n")[0]
            return cpe
        else:
            self.ptjsonlib.end_error(f"Error parsing CPE from query: {self.args.search}", condition=self.args.json)

    def is_cpe(self, string: str) -> bool:
        """Check if string is a valid CPE 2.3 formatted string"""
        if not string.startswith("cpe:2.3:"):
            return False

        parts = string.split(":")
        # cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
        if len(parts) != 13:
            return False

        part = parts[2]
        if part not in ("a", "o", "h"):  # a = application, o = OS, h = hardware
            return False

        return True


    def call_external_script(self, subprocess_args: list) -> str:
        """
        Run an external script in a pseudo-TTY so TTY-based progress bars render correctly,
        while capturing all output for later use.
        """
        master_fd, slave_fd = pty.openpty()

        proc = subprocess.Popen(
            subprocess_args,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            close_fds=True,
        )
        os.close(slave_fd)

        output_lines = []
        buffer = ''
        do_print = getattr(self.args, "verbose", False) and not getattr(self.args, "json", False)

        try:
            while True:
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if master_fd in r:
                    try:
                        data = os.read(master_fd, 1024).decode(errors="ignore")
                    except OSError:
                        break  # PTY closed by child
                    if not data:
                        break
                    # live print if verbose and not json
                    if do_print:
                        sys.stdout.write(data)
                        sys.stdout.flush()
                    # accumulate output
                    buffer += data
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        output_lines.append(line + '\n')
                # break if process exited and no more data
                if proc.poll() is not None and not select.select([master_fd], [], [], 0.0)[0]:
                    break
            # flush remaining buffer
            if buffer:
                output_lines.append(buffer)
        finally:
            try:
                os.close(master_fd)
            except Exception:
                pass
            proc.wait()

        full_output = ''.join(output_lines)
        return full_output

    def _check_if_db_loaded(self):
        """Check if cpe .db file is loaded with data"""
        db_file = os.path.expanduser("~/.penterep/.ptvulns/data/deprecated-cpes.json")
        if not os.path.exists(db_file):
            raise FileNotFoundError(f"Database file not found: {db_file}")

def get_help():
    """
    Generate structured help content for the CLI tool.

    Returns:
        list: A list of dictionaries, where each dictionary represents a section of help
              content (e.g., description, usage, options). The 'options' section includes
              available command-line flags and dynamically discovered test modules.
    """

    return [
        #{"description": ["ptvulns"]},
        {"usage": ["ptvulns <options>"]},
        {"usage_example": [
            "ptvulns -s \"Apache 2.3\"",
            "ptvulns -s cpe:2.3:a:apache:camel:2.3.0:*:*:*:*:*:*:*  ",
        ]},
        {"options": [
            ["-s",  "--search",                 "<search>",         "Search string for vulns"],
            ["-vv", "--verbose",                "",                 "Show verbose output"],
            ["-U",  "--update",                "",                  "Update CPE db"],
            #["-wd", "--without-details",                "",         "Show CVE without additional requests"],
            ["-gv", "--group-vulns",                "",             "Group vulnerabilities for JSON"],
            ["-v",  "--version",                "",                 "Show script version and exit"],
            ["-h",  "--help",                   "",                 "Show this help message and exit"],
            ["-j",  "--json",                   "",                 "Output in JSON format"],
        ]
        }]

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help="False", description=f"{SCRIPTNAME} <options>")
    parser.add_argument("-s",  "--search",         type=str, required=False)
    parser.add_argument("-U", "--update",        action="store_true")
    parser.add_argument("-vv", "--verbose",        action="store_true")
    parser.add_argument("-j",  "--json",           action="store_true")
    parser.add_argument("-wd",  "--without-details",           action="store_true")
    parser.add_argument("-gv",  "--group-vulns",           action="store_true")
    parser.add_argument("-v",  "--version",        action='version', version=f'{SCRIPTNAME} {__version__}')

    parser.add_argument("--socket-address",          type=str, default=None)
    parser.add_argument("--socket-port",             type=str, default=None)
    parser.add_argument("--process-ident",           type=str, default=None)

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        ptprint(help_print(get_help(), SCRIPTNAME, __version__))
        sys.exit(0)

    args = parser.parse_args()

    print_banner(SCRIPTNAME, __version__, args.json, 0)
    return args

def main():
    global SCRIPTNAME
    SCRIPTNAME = os.path.splitext(os.path.basename(__file__))[0]
    args = parse_args()
    script = PtVulns(args)
    script.run()

if __name__ == "__main__":
    main()
