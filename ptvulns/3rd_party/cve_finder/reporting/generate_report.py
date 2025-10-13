import shutil
import logging
from html import escape

db_names = {
    "nvd": "NVD",
    "mitre": "CVE List",
    "exploit_db": "ExploitDB",
    "exploit-db": "ExploitDB",
    "cwe": "CWE Database",
    "cwe-database": "CWE Database",
    "osv": "OSV",
}

db_links = {
    "nvd": "https://nvd.nist.gov/vuln/detail/{cve_id}",
    "mitre": "https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
    "exploit_db": "https://www.exploit-db.com/search?cve={cve_id}",
    "exploit-db": "https://www.exploit-db.com/search?cve={cve_id}",
    "osv": "https://osv.dev/vulnerability/{cve_id}",
}


def get_severity(score):
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


def icon_html(verified):
    """
    Generate an SVG icon for verification status.
    """
    color = "#4CAF50" if verified else "#ccc"
    return (
        f'<svg style="width:16px;height:16px;fill:{color};vertical-align:middle;" viewBox="0 0 24 24">'
        '<path d="M12,2A10,10 0 1,0 22,12A10,10 0 0,0 12,2M10,17L5,12L6.41,10.58L10,14.17L17.59,6.58L19,8L10,17Z" />'
        "</svg>"
    )


def render_field(label, value, verified_text):
    """
    Render a generic field with a label, value, and verification status.
    """
    return (
        "<div class='field'>"
        f"<div class='field-name'>{label}:</div>"
        f"<div>{value}</div>"
        f"<div class='verified-by'>{verified_text}</div>"
        "</div>"
    )


def render_score(details):
    """
    Render the score field with severity levels.
    """
    score_groups = {}
    for src, val in details.get("values", {}).items():
        score_groups.setdefault(val, []).append(db_names.get(src, src))

    score_display = ""
    for score, srcs in score_groups.items():
        severity = get_severity(score)
        color_class = f"severity-{severity.lower()}"
        score_display += (
            f'<p>{score} ({", ".join(srcs)}): <span class="{color_class}">{severity}</span></p>'
        )

    verified_text = generate_verified_text(details)
    return render_field("Score", score_display, verified_text)


def render_vector(details):
    """
    Render the vector field with CVSS links.
    """
    vector_groups = {}
    for src, val in details.get("values", {}).items():
        vector_groups.setdefault(val, []).append(db_names.get(src, src))

    vector_display = ""
    for vector, srcs in vector_groups.items():
        version = vector.split("/")[0].split(":")[-1].replace(".", "-")
        cvss_url = f"https://www.first.org/cvss/calculator/{version}#{vector}"
        vector_display += (
            f'<a href="{cvss_url}" target="_blank">{vector}</a> ({", ".join(srcs)})<br>'
        )

    verified_text = generate_verified_text(details)
    return render_field("Vector", vector_display, verified_text)


def generate_verified_text(details):
    """
    Generate the verification status HTML for a field.
    """
    mark = icon_html(details.get("verified", False))
    if "verified_by" in details and details["verified_by"]:
        verified_by_names = ", ".join(
            db_names.get(src, src) for src in details["verified_by"]
        )
        return f'<div class="verified-wrapper">{mark} Verified by: {verified_by_names}</div>'
    else:
        return f'<div class="verified-wrapper">{mark} Unverified</div>'


def render_cwe_metadata(entry, details):
    """
    Render CWE metadata as a list with links to the CWE database.
    """
    cwe_ids = entry.get("cwe_id", [])
    cwe_meta = details if isinstance(details, list) else []
    cwe_lines = []
    for idx, cwe in enumerate(cwe_meta):
        cwe_id = ""
        if idx < len(cwe_ids):
            cwe_id = cwe_ids[idx].get("id", "")
        cwe_name = cwe.get("name", "")
        desc = escape(cwe.get("description", ""))
        if cwe_id.startswith("CWE-") and cwe_name:
            cwe_num = cwe_id.replace("CWE-", "")
            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
            link_text = f"{escape(cwe_id)} - {escape(cwe_name)}"
            link_html = f'<a href="{cwe_url}" target="_blank">{link_text}</a>'
        elif cwe_id and cwe_name:
            link_html = f"{escape(cwe_id)} - {escape(cwe_name)}"
        elif cwe_name:
            link_html = f"{escape(cwe_name)}"
        else:
            link_html = f"{escape(cwe_id)}"
        cwe_lines.append(f"{link_html}<p>{desc}</p>")
    value = "<br>".join(cwe_lines)
    label = "CWE List"
    verified_text = ""
    return render_field(label, value, verified_text)


def render_exploit(details):
    """
    Render exploit info with name linked to the database, no source display.
    """
    desc = escape(details.get("description", ""))
    link = details.get("link")
    if link:
        name_link = f'<a href="{escape(link)}" target="_blank">{desc}</a>'
    else:
        name_link = f"{desc}"
    value = f"{name_link}"
    label = "Exploit"
    verified_text = ""
    return render_field(label, value, verified_text)


def generate_html_report(unified_data):
    """
    Generate an HTML report from unified CVE data.
    """
    html = """
    <html>
    <head>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; text-align:left; }
            h3 { margin-top: 4px; }
            p { margin: 6px 0; }
            .cve-container { margin-bottom: 25px; padding: 15px; border: 1px solid #ccc; border-radius: 5px; text-align:left; }
            .field { margin-top: 12px; text-align:left; }
            .field-name { font-weight: bold; display: block; margin-bottom: 6px; text-align:left; }
            .verified-by { font-size: 0.9em; color: #555; margin-top: 6px; margin-right:8px; text-align:left; }
            .verified-wrapper { display: inline-flex; align-items: center; gap: 0.3em; }
            .severity-critical { color: red; }
            .severity-high { color: darkorange; }
            .severity-medium { color: goldenrod; }
            .severity-low { color: green; }
            .severity-none, .severity-unknown { color: gray; }
        </style>
    </head>
    <body>
        <h2 style="text-align:left;">CVE Detailed Unified Report</h2>
    """

    for entry in unified_data:
        cve_id = entry.get("id", {}).get("selected", "Unknown CVE ID")
        html += f"<div class='cve-container'><h3>{escape(cve_id)}</h3>"

        if "sources" in entry:
            readable_sources = [db_names.get(src, src) for src in entry["sources"]]
            html += render_field("Sources used", ", ".join(readable_sources), "")

        for field, details in entry.items():
            if field in ["id", "cwe_id", "sources"]:
                continue

            if field == "score":
                html += render_score(details)
            elif field == "vector":
                html += render_vector(details)
            elif field == "cwe_metadata":
                html += render_cwe_metadata(entry, details)
            elif field == "exploit":
                if isinstance(details, dict):
                    html += render_exploit(details)
            else:
                label = (
                    "Description"
                    if field == "desc"
                    else field.replace("_", " ").capitalize()
                )
                value = escape(details.get("selected", "Unknown"))

                # Add links to all used databases for this CVE at the end of the description
                if field == "desc":
                    cve_id_str = entry.get("id", {}).get("selected", None)
                    sources = entry.get("sources", [])
                    links = []
                    if cve_id_str and cve_id_str.startswith("CVE-"):
                        for src in sources:
                            if src in ("exploit-db", "exploit_db"):
                                continue
                            url_template = db_links.get(src)
                            if url_template:
                                url = url_template.format(cve_id=cve_id_str)
                                links.append(f'<a href="{url}" target="_blank">{db_names.get(src, src)}</a>')
                        if links:
                            value += "<p>Read more: " + ", ".join(links) + "</p>"

                verified_text = generate_verified_text(details)
                html += render_field(label, value, verified_text)

        html += "</div>"

    html += "</body></html>"
    return html


def generate_pdf_from_html(html_content, pdf_filename):
    """
    Generate a PDF file from HTML content using pdfkit and wkhtmltopdf.
    """

    if not shutil.which("wkhtmltopdf"):
        logging.error(
            "wkhtmltopdf is not installed. Please install it to enable PDF generation."
        )
        return

    try:
        import pdfkit
        pdfkit.from_string(html_content, pdf_filename)
        logging.info(f"PDF report successfully written to {pdf_filename}")
    except Exception as e:
        logging.error(f"Error while generating PDF: {e}", exc_info=True)
