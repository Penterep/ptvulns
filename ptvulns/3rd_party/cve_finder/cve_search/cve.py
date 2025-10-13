
class Cve:
    def __init__(self,source_db, id, date_published, desc, score, vector, cwe_id ):
        self.source_db = source_db
        self.id = id
        self.date_published = date_published
        self.desc = desc
        self.score = score
        self.vector = vector
        self.cwe_id = cwe_id