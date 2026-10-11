# Changelog

## 0.0.19

- Require an exact software version in CPE searches when using `--json`. Missing or wildcard versions terminate with `end_error` and report the total number of CVE records found, including zero.
- Replace single line breaks in CVE descriptions with spaces while preserving paragraph breaks in JSON and unstructured descriptions.
- Improve console readability with highlighted CVE IDs, muted metadata labels, green exploit availability indicators, and spacing between CVE records.
- Display recognized description sections (`Issue summary`, `Impact summary`, `CWE`, `Description`, and `FIPS Impact`) on separate lines, indented by two spaces with muted headings. Join paragraphs within each section into a continuous text block.
- Keep console formatting changes separate from JSON output.
