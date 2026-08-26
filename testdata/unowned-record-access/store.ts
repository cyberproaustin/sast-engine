// Stands in for a data-access layer. What matters is that these operations select ONE
// record using the identifier they are given.
//
// Written as CLASSES rather than object literals for the reason the ownership fixture
// gives: an object literal types as `__object`, which says nothing about whether records
// live behind it, and a real ORM model is a named type.
class StrategyModel {
  async findFirst(args: unknown) {
    return { id: "s1", projectId: "p1", userId: "u1" };
  }
  async update(args: unknown) {
    return { id: "s1" };
  }
  async delete(args: unknown) {
    return { id: "s1" };
  }
}

class ProjectModel {
  async delete(args: unknown) {
    return { id: "p1" };
  }
  async update(args: unknown) {
    return { id: "p1" };
  }
}

class LinkModel {
  async findFirst(args: unknown) {
    return { id: "l1" };
  }
  async delete(args: unknown) {
    return { id: "l1" };
  }
}

class SubscriptionModel {
  async delete(args: unknown) {
    return { id: "sub1" };
  }
}

export const store = {
  strategy: new StrategyModel(),
  project: new ProjectModel(),
  link: new LinkModel(),
  subscription: new SubscriptionModel(),
};

// The application's own existence test, which is the second spelling this corpus is
// about. It answers whether a row is THERE. Nothing in the answer says who owns it, and
// nothing in the call mentions the scope the caller was authorized for.
export async function featureExists(featureId: string): Promise<boolean> {
  return featureId !== "";
}

// A real ownership lookup, for contrast: it is handed BOTH identifiers, so a row it
// returns is one that belongs to the project the caller was authorized for.
export async function findStrategyInProject(strategyId: string, projectId: string) {
  return { id: strategyId, projectId };
}
