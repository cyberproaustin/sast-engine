// Stands in for a data-access layer.
exports.users = {
  find: async (id) => ({ id, role: "user", balance: 0 }),
};
