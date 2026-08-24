// Stands in for any data-access layer. What matters is that these operations select
// ONE record using the identifier they are given.
export const prisma = {
  order: {
    findUnique: async (args: unknown) => ({ id: "1", userId: "u1", total: 0 }),
    findMany: async (args: unknown) => [],
    delete: async (args: unknown) => ({ id: "1" }),
  },
  user: {
    findUnique: async (args: unknown) => ({ id: "u1", username: "a" }),
  },
};
