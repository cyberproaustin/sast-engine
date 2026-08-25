// Stands in for a data-access layer. What matters is that these operations select ONE
// record using the identifier they are given.
//
// Written as CLASSES rather than object literals on purpose. An object literal types as
// `__object`, an anonymous type that says nothing about whether records live behind it --
// and the engine treats that as unanswerable and costs the finding its confidence, which
// is correct for a namespace an application assembles out of other modules. A real ORM
// model is a named type, and this fixture should look like one.
class OrderModel {
  async findUnique(args: unknown) {
    return { id: "1", userId: "u1", total: 0 };
  }
  async findMany(args: unknown) {
    return [];
  }
  async delete(args: unknown) {
    return { id: "1" };
  }
  async update(args: unknown) {
    return { id: "1" };
  }
}

class UserModel {
  async findUnique(args: unknown) {
    return { id: "u1", username: "a" };
  }
}

export const prisma = {
  order: new OrderModel(),
  user: new UserModel(),
};
