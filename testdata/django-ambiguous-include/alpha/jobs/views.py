"""One of the two modules `jobs.views` could mean, and the dangerous one.

NOT A FINDING, on purpose. The flow is real -- a query parameter is concatenated into a
shell command -- and no route in this program reaches this function: the only registration
that names it names a module two files answer to. Claiming it would mean printing a path,
and the path would be a guess about which tree the deployment installed.

If the resolver ever picks one of the two, this becomes a reported command injection at
`/run/` and the corpus fails with a FALSE POSITIVE. That is the whole assertion.
"""
import subprocess

from django.http import HttpResponse


def execute(request):
    task = request.GET["task"]
    return HttpResponse(subprocess.check_output("jobctl run " + task, shell=True))
