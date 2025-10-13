# CVE Searcher and Analyzer

## Description
An experimental version of a tool that allows the user to aggregate information from multiple CVE and other related databases into a report. Uses a single or multiple CPEs as input.

## Table of Contents
- [CVE Searcher and Analyzer](#cve-searcher-and-analyzer)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
    - [Additional Dependency: wkhtmltopdf](#additional-dependency-wkhtmltopdf)
  - [Usage](#usage)
  - [Features](#features)
  - [Database Extension](#database-extension)
  - [Contributing](#contributing)
  - [License](#license)

## Installation
Step-by-step instructions on how to install and set up the project.

Clone the repository:
```bash
git clone https://gitlab.utko.feec.vutbr.cz/infosec/cve-search
```

We recommend using a virtual environment to avoid conflicts with other projects:
```bash
python3 -m venv ~/cve-search
source ~/cve-search/bin/activate
```

Install the required dependencies:
```bash
pip install -e .
```

### Additional Dependency: wkhtmltopdf

To generate PDF reports, this tool requires `wkhtmltopdf`. 

**Windows**:

Download and install the command-line tool from [wkhtmltopdf.org](https://wkhtmltopdf.org/downloads.html). 

**Fedora/RHEL**:
```bash
sudo dnf install wkhtmltopdf
```

**Debian/Ubuntu**: 
```bash
sudo apt install wkhtmltopdf
```

Ensure the `wkhtmltopdf.exe` is added to your system PATH.

## Usage
In its current version, the tool supports either a single CPE or a file containing multiple CPEs separated by commas. Examples:

```bash
cve-search --help 
cve-search --cpe cpe:2.3:a:xwiki:admin_tools:4.4:*:*:*:*:*:*:*
cve-search --file ./cve_finder/test_cpe.txt
cve-search --verify path_to_generated_file.json
```

Example of a CPE file:
```
cpe:2.3:a:xwiki:admin_tools:4.4:*:*:*:*:*:*:*,cpe:2.3:o:microsoft:windows_10:2019:*:*:*:enterprise_ltsc:*:*:*,cpe:2.3:a:apache:http_server:2.4.12:*:*:*:*:*:*:*
```

## Features
- Querying and aggregating records from CVE open databases.
- Retrieving additional information from databases such as the CWE database and ExploitDB.
- Analyzing the information and generating a report.
- Future plans: Ability to re-verify an existing report to see potential changes (New CVEs, changes in scoring) since the report was generated.

## Database Extension
- In its current state, the tool works by default with the NVD and CVE List database. The OSV database is optional, since it doesn't provide much information.
- The tool works independently of the number of source databases used.
- To add a new database, appropriate functions need to be created in [request_handler](./cve_finder/cve_search/request_handler.py) and [normalizer](./cve_finder/normalizer/normalizer.py), and then called from [parser](./cve_finder/argument_parser/parser.py).
- For reporting, add the URL and database source name to the [report generation enums](./cve_finder/reporting/generate_report.py).

## Contributing

Guidelines for contributing to the project:
1. Fork the repository
2. Create a new branch
3. Commit your changes
4. Submit a merge request

## License
This project is licensed under the [Apache License 2.0 ](https://www.apache.org/licenses/LICENSE-2.0).