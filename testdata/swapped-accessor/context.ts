// The request context, in the shape a multi-tenant server actually writes it.
//
// Two accessors hang off one object and they are not interchangeable. `repo` is
// constructed for the caller and cannot see outside the project they are a member of;
// `systemRepo` is constructed with the server's own authority and can see everything.
// Handlers legitimately reach for the second one -- a field the caller must not be able
// to write is exactly what an elevated repository is for -- so its presence is not the
// defect. Which one the permission question was asked about is.
//
// Written as CLASSES rather than object literals for the reason the ownership fixture
// gives: an object literal types as `__object`, and a real repository is a named type.
class Repository {
  constructor(readonly projectId: string | null) {}

  // The permission questions. Each is about THIS repository: a repository built for the
  // caller answers about the caller, and a repository built with the server's authority
  // answers "yes" to everything.
  async isProjectAdmin(): Promise<boolean> {
    return this.projectId !== null;
  }
  async isSuperAdmin(): Promise<boolean> {
    return this.projectId === null;
  }
  // The scoped form of the same question: handed the record, it answers about that
  // record. A handler that asks this has named what it is asking about.
  async isAllowedOn(resourceId: string): Promise<boolean> {
    return resourceId !== "" && this.projectId !== null;
  }

  async readResource(kind: string, id: string, within?: unknown) {
    return { id, kind, project: this.projectId, secret: "" };
  }
  async updateResource(resource: unknown) {
    return resource;
  }
  async withTransaction<T>(work: (tx: Repository) => Promise<T>): Promise<T> {
    return work(this);
  }
}

class Cache {
  has(key: string): boolean {
    return key !== "";
  }
}

class RequestContext {
  readonly repo: Repository;
  readonly systemRepo: Repository;
  readonly cache: Cache;
  readonly project: { id: string };

  constructor(projectId: string) {
    this.repo = new Repository(projectId);
    this.systemRepo = new Repository(null);
    this.cache = new Cache();
    this.project = { id: projectId };
  }
}

// The authenticated context, fetched the way frameworks with request-local storage hand
// it over: no argument, because the request is already in scope somewhere else.
export function getAuthenticatedContext(): RequestContext {
  return new RequestContext("project-1");
}

// A policy object belonging to something OTHER than the request context, for the
// handler that checks one object and operates on an unrelated one.
class Policy {
  async isAllowed(): Promise<boolean> {
    return true;
  }
}

export const limits = { policy: new Policy() };

export function generateSecret(length: number): string {
  return String(length);
}
