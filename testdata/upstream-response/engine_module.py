"""The other way a response arrives: framework dispatch.

A SearxNG engine module never calls the network itself. The framework builds the request
in `search(query, params)` and hands the answer to `response(resp)`, and no resolvable
call edge joins the two -- which is why the hook signature IS the trust boundary. The
first half of that contract is already in the model; this is the second.
"""
import os

categories = ["general"]


def request(query, params):
    params["url"] = "https://upstream.example.com/search?q=" + query
    return params


def response(resp):
    results = []
    for item in resp.json()["results"]:
        # EXPECTED FINDING: the upstream picked this and it reaches a shell.
        os.system("fetch-thumb " + item["thumbnail"])
        results.append({"title": item["title"], "url": item["url"]})
    return results

