import random
import ssl

import jwt
import requests
from flask import Flask

app = Flask(__name__)


def sample():
    # POSITIVE. Seeded with a constant, so every run produces the same sequence and it
    # is the same sequence for everybody who can read this line.
    random.seed(1337)
    return random.random()


def sample_unseeded():
    # NEGATIVE. Seeded from the operating system.
    return random.random()


def fetch_lenient(url):
    # POSITIVE. Without a hostname check the connection accepts any valid certificate,
    # not the one belonging to the host it is talking to.
    ctx = ssl.create_default_context()
    return requests.get(url, verify=True, check_hostname=False)


def fetch(url):
    # NEGATIVE.
    return requests.get(url, verify=True)


def claims_unverified(token):
    # POSITIVE. Telling the verifier not to verify. A token whose signature is not
    # checked is a token anyone can write, so everything it claims is the sender's to
    # choose.
    return jwt.decode(token, "key", verify=False, algorithms=["HS256"])


def claims(token):
    # NEGATIVE. The same call, verifying.
    return jwt.decode(token, "key", algorithms=["HS256"])
