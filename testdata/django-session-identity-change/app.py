"""Session fixation is an identity transition whose old identifier survives.

The first function is wger's shape: Django changes the authenticated identity and rotates
the session key inside ``login``, then the application remembers the prior user in its own
namespaced session field. That metadata write is neither half of the defect.

The second function calls an application login operation over the same request but does
not rotate. Only that identity change is a finding.
"""

from django.contrib.auth import login as django_login
from project.auth import login


def switch_user(request, user, original_user_pk):
    # NEGATIVE. Django cycles or flushes the session key before it installs this user.
    django_login(request, user, "django.contrib.auth.backends.ModelBackend")

    # Also negative. This is exactly wger's follow-up write: application metadata under
    # a namespace, carrying the identity the trainer may later switch back to.
    request.session["trainer.identity"] = original_user_pk


def switch_user_without_rotation(request, user):
    # POSITIVE. This application login changes the request's identity, and unlike
    # Django's operation above it provides no intrinsic or explicit session rotation.
    login(request, user)
