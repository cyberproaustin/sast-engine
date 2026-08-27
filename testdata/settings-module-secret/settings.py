"""A module's top level IS the configuration namespace, in the framework that has no
configuration object.

The secret rules match a write into something -- `app.config["SECRET_KEY"]`,
`app.secret_key` -- because in Flask there is an object to write into. Django has none:
`django.conf.settings.SECRET_KEY` reads the module-level `SECRET_KEY` of whichever module
the deployment names, so the configuration write is a bare assignment with no base and no
property, and every rule about a configuration key was blind to the whole framework.

The value half is the other spelling of the same fact. `X || literal` says "default" with
an operator; every library says it with an argument, and the argument after the KEY is
the one that means it. Excluding the first argument is the whole rule -- it is the name
of the variable being read, it is credential-shaped in every one of these calls, and
admitting it would report the correct way to write the line.
"""

import os

from environs import Env

env = Env()

# POSITIVE. doccano's line: a repository-known fallback that becomes the signing key
# whenever the deployment supplies nothing, which is what the shipped image and the
# documented run command both do.
SECRET_KEY = env("SECRET_KEY", "v8sk33sy82!uw3ty=!jjv5vp7=s2phrzw(m(hrn^f7e_#1h2al")

# POSITIVE. The stdlib spelling of the same shape.
JWT_SIGNING_KEY = os.environ.get("JWT_SIGNING_KEY", "django-insecure-9f2h3k4j5l6m7n8o")

# POSITIVE. The keyword spelling, which is how python-decouple and environs both write it.
DATABASE_PASSWORD = env.str("DATABASE_PASSWORD", default="hunter2andthensome")

# NEGATIVE, and the near miss the first-argument exclusion exists for. This is the
# CORRECT way to write the line, and the key name is credential-shaped exactly as the
# fallbacks above are -- so a rule that read any literal in the call would report the fix
# it was recommending.
REAL_SECRET_KEY = env("REAL_SECRET_KEY")

# NEGATIVE. Read from the environment with no fallback anywhere.
MAIL_PASSWORD = os.environ["MAIL_PASSWORD"]

# NEGATIVE. A default that is not a value capable of serving as the credential.
SESSION_SECRET = os.environ.get("SESSION_SECRET", "")

# NEGATIVE. A default this program falls back to and no credential word in the key.
LOG_LEVEL = os.environ.get("LOG_LEVEL", "verbose-debugging")

# NEGATIVE. A double-submit CSRF token is not a secret in this sense, and the key names a
# header rather than holding one.
CSRF_SECRET_HEADER = os.environ.get("CSRF_SECRET_HEADER", "X-CSRF-Token")
