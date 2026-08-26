// The store the handlers write to. Separate module so a write is a resolved call into
// another file, which is what it is in the repository this corpus came from.
module.exports = {
  create(name) {
    return name;
  },
  read(id) {
    return id;
  },
};
