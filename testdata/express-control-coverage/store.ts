// The vocabulary the handlers are written against. Nothing here is judged; it exists so
// the calls in the other files resolve to something.

export type Snapshot = { path: string; owner: string };

export const archive = {
  async canViewSnapshot(_req: unknown, _snapshot: Snapshot | undefined) {
    return false;
  },
  async canViewProfile(_req: unknown, _profile: unknown) {
    return false;
  },
  async canEditDocument(_req: unknown, _document: unknown) {
    return false;
  },
  async canDeleteDocument(_req: unknown, _document: unknown) {
    return false;
  },
  async profileOf(owner: string) {
    return { owner };
  },
  async loadDraft(id: string) {
    return { id, draft: true };
  },
  async loadPublished(id: string) {
    return { id, draft: false };
  },
  async commit(_document: unknown) {
    return true;
  },
};

export const permissions = {
  async visibleTo(_owner: number) {
    return false;
  },
  async permittedKinds(_kind: string) {
    return false;
  },
};

export async function lookupById(id: string): Promise<Snapshot | undefined> {
  return { path: `by-id/${id}`, owner: "someone" };
}

export async function publicQuery(owner: string, slug: string): Promise<Snapshot | undefined> {
  return { path: `${owner}/${slug}`, owner };
}

export function healthOf() {
  return "up";
}

export function serializerFor(kind: string) {
  return { kind };
}

export class Condition {
  constructor(
    public field: string,
    public value: string,
  ) {}
}

export class Disjunction {
  constructor(public terms: unknown[]) {}
}

export function parseCriteria(criteria: string) {
  return { criteria };
}

export const logger = {
  warn(_message: string, _detail: unknown) {},
};
