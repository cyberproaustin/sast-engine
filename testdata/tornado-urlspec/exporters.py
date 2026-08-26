"""NEGATIVE. A module-level list of two-element tuples, each one a string and a class this
program defines, and not one of them is a route.

A pair of a name and a class is one of the most common records in any codebase -- a
choices list, a dispatch table, a registry of renderers -- and it is written in exactly
the same characters a route table is. What separates the table that IS one is that its
first element is a PATH: Tornado matches a pattern against the request path, which always
begins with a slash.
"""


class CsvExporter:
    def render(self, rows):
        return "\n".join(",".join(row) for row in rows)


class JsonExporter:
    def render(self, rows):
        return str(rows)


EXPORTERS = [
    ("text/csv", CsvExporter),
    ("application/json", JsonExporter),
]
