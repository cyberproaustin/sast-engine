const db = require("./db");

function getProduct(product_id) {
  return db.one("SELECT * FROM products WHERE id = '" + product_id + "';");
}

function search(query) {
  return db.many("SELECT * FROM products WHERE name ILIKE '%" + query + "%';");
}

// The export table. The values NAME functions declared above rather than holding them
// inline, which is the ordinary shape and the one that stopped resolution dead.
const actions = {
  getProduct: getProduct,
  search: search,
};

module.exports = actions;
