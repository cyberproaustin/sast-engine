"""The request context, and the two accessors that hang off it.

`repo` is built for the caller and cannot see outside the tenant they belong to.
`system_repo` is built with the server's own authority and can see everything. Reaching
for the second one is not the defect -- writing a field the caller must not be able to set
is exactly what it is for. Which one the permission question was asked about is.
"""


class Repository:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id

    def is_tenant_admin(self):
        return self.tenant_id is not None

    def read_record(self, kind, record_id, within=None):
        return {"id": record_id, "kind": kind, "tenant": self.tenant_id}

    def update_record(self, record):
        return record


class Cache:
    def has(self, key):
        return key != ""


class RequestContext:
    def __init__(self, tenant_id):
        self.repo = Repository(tenant_id)
        self.system_repo = Repository(None)
        self.cache = Cache()
        self.tenant = {"id": tenant_id}


def get_authenticated_context():
    """Fetched the way frameworks with request-local storage hand it over: no argument,
    because the request is already in scope somewhere else."""
    return RequestContext("tenant-1")
