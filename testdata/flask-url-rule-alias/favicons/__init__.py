# The re-export the definition table does not follow: `favicon_proxy` is defined in
# `proxy.py` and imported here, so `favicons.favicon_proxy` names a function this file
# does not declare.
from .proxy import favicon_proxy

__all__ = ["favicon_proxy"]
