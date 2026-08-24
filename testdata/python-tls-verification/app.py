"""A connection that does not verify its peer authenticates nobody.

Transport encryption without certificate validation protects against a passive listener
and against nothing else: anyone able to answer for the address can read and rewrite the
traffic. The keyword says so outright, which is what makes this decidable without any
dataflow at all.

Every keyword argument is checked, not the first one found. Reading whichever came out of
the map first made a call with two keywords report or not report depending on the run, and
a scanner that answers differently on identical input is worse than one that answers
wrongly: the wrong answer can at least be investigated.
"""
import requests


def fetch_insecure(url):
    return requests.get(url, verify=False)


def fetch_insecure_with_neighbours(url):
    # The disallowed keyword is not the first one written.
    return requests.get(url, timeout=5, headers={"accept": "json"}, verify=False)


def fetch(url):
    return requests.get(url, timeout=5)


def post_insecure(url, body):
    return requests.post(url, json=body, verify=False)
