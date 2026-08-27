import express from "express";

const app = express();

app.get("/whole", (req, res) => {
  res.render("whole", { target: req.query.target });
});

app.get("/part", (req, res) => {
  res.render("part", { name: req.query.name });
});

app.get("/encoded-part", (req, res) => {
  res.render("part", { name: encodeURIComponent(req.query.name as string) });
});

app.get("/dom", (req, res) => {
  const image = document.createElement("img");
  image.src = "/images/" + req.query.name;
  const link = document.createElement("a");
  link.href = req.query.target as string;
  const safe = document.createElement("img");
  safe.src = "/images/" + encodeURIComponent(req.query.name as string);
  res.json({ ok: true });
});

export default app;
