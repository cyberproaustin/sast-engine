"""Where the digests land, a module away from the routes that compute them."""
import hashlib
import os

CACHE_DIR = "/var/cache/thumbs"

ACCOUNTS = {}


class Account:
    def __init__(self, name):
        self.name = name
        self.password_hash = ""


def set_password(name, password):
    # POSITIVE, reported here rather than at the route. The comparison this digest will
    # lose to happens in another request and usually in another function, so there is no
    # flow to follow -- and none is needed. The write says it: this digest is what the
    # account's password now IS, and anything hashing to it is that password.
    account = ACCOUNTS.setdefault(name, Account(name))
    account.password_hash = hashlib.new("md5", password.encode()).hexdigest()
    return account


def cache_path(url):
    # NEGATIVE. The digest is a filename. `hashlib.new` is the other spelling and the
    # algorithm is just as plainly written; what makes this silent is not how the
    # algorithm was named but that nothing is decided by the answer.
    return os.path.join(CACHE_DIR, hashlib.new("md5", url.encode()).hexdigest() + ".png")
