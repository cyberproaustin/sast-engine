"""The authentication layer the context builders call. Bodies are deliberately empty:
what this corpus is about is which of these a function calls, not what any of them does.
"""


def authenticate(request=None):
    return None


def token_from_request(request):
    return ""


def decode(token):
    return {}


def app_for(request):
    return None
