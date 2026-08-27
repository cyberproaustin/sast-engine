"""What a query resolver reaches."""

import subprocess


def find_report(slug):
    # The caller chooses the slug and it becomes a shell word.
    return subprocess.check_output("report-tool --find " + slug, shell=True)
