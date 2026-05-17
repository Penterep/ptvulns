
class Cve:
    def __init__(
        self,
        source_db,
        id,
        date_published,
        desc,
        score,
        vector,
        cwe_id,
        exploitability_score="",
        impact_score="",
        cvss_impact="",
        affected_versions="",
        fixed_versions="",
        references="",
    ):
        self.source_db = source_db
        self.id = id
        self.date_published = date_published
        self.desc = desc
        self.score = score
        self.vector = vector
        self.cwe_id = cwe_id
        self.exploitability_score = exploitability_score
        self.impact_score = impact_score
        self.cvss_impact = cvss_impact
        self.affected_versions = affected_versions
        self.fixed_versions = fixed_versions
        self.references = references
