"""The root URLconf, naming two things that TWO modules each answer to.

AMBIGUITY RESOLVES TO NOTHING. Resolving a dotted name against a source tree is a suffix
match -- an application writes `plane.app.urls` against a source root of `apps/api/`, and
no module in it spells its own name the way a scanner's module ids do. A suffix that two
modules end with says nothing about which of them the loader will find, and the file that
would settle it is a deployment's `sys.path` rather than any source in the repository.

A phantom route is worse than a missing one. An entry point is what a finding is anchored
to, and these findings are sent to maintainers: a route we invented sends someone to an
address that does not exist, and everything said about it is unfalsifiable. So a name two
modules answer to mounts nothing and reaches nothing.
"""
from django.urls import include, path

from jobs import views as job_views

urlpatterns = [
    # AMBIGUOUS MOUNT. `alpha/billing/urls.py` and `beta/billing/urls.py` both end with
    # `billing.urls`. Neither takes this prefix: both of their routes stay at the path
    # their own file writes, which is what the surface below shows.
    path("pay/", include("billing.urls")),
    # AMBIGUOUS VIEW. `alpha/jobs/views.py` and `beta/jobs/views.py` both end with
    # `jobs.views`, and one of the two `execute` functions runs a shell command built out
    # of a query parameter. This registration therefore reaches NOTHING -- naming the
    # wrong one would report a command injection at a path that handler does not serve,
    # against a file the deployment may not even contain.
    path("run/", job_views.execute),
]
