// Two weaknesses that share nothing except being cheap to describe once the vocabulary
// exists: neither needed a line of engine code.
//
// An open redirect matters because the application lends its own name to a destination
// someone else chose, which is what makes a phishing link look like it came from you. A
// deserializer matters because it calls constructors rather than parsing, so the payload
// chooses what runs.
import express from "express";
import serialize from "node-serialize";

const app = express();

app.get("/go", (req, res) => {
  // The caller names the destination.
  res.redirect(String(req.query.next));
});

app.get("/profile", (req, res) => {
  // A path inside this application. It cannot leave, so it is not this weakness.
  res.redirect(`/users/${req.query.id}`);
});

app.post("/restore", (req, res) => {
  // Reconstructs objects, including functions it then invokes.
  const state = serialize.unserialize(String(req.body.state));
  res.json({ restored: Boolean(state) });
});

app.post("/parse", (req, res) => {
  // JSON.parse builds data, never behaviour. Not a deserializer in this sense.
  res.json({ parsed: JSON.parse(String(req.body.state)) });
});

export default app;
