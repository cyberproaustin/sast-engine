// A router that arrives as a parameter, which is how a great deal of Express code is
// written: there is no binding to find and the SHAPE is the evidence. Still a route.
module.exports = (router) => {
  router.post("/things", (req, res) => {
    res.json({ ok: true });
  });
};
