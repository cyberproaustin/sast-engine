const express = require("express");
const db = require("./db");
const app = express();

// Every return is a string written here. Nothing a caller sends can come back out of it.
function describeError(code) {
  switch (code) {
    case 404:
      return "File not found.";
    case 401:
      return "Invalid archived format token.";
    case 429:
      return "Too many requests.";
    default:
      return "An internal error occurred, please contact the support team.";
  }
}

function mimeFor(name) {
  if (name.endsWith(".pdf")) return "application/pdf";
  if (name.endsWith(".png")) return "image/png";
  if (name.endsWith(".html")) return "text/html";
  return "image/jpeg";
}

const kindOf = (name) => (name.endsWith(".json") ? "structured" : "opaque");

// NEGATIVE for the summary: one return interpolates the parameter.
function describePath(name) {
  if (!name) return "no path given";
  return `could not read ${name}`;
}

// NEGATIVE for the summary: the value comes back out of a store.
function storedName(id) {
  if (!id) return "anonymous";
  return db.read(id);
}

app.get("/a", (req, res) => {
  res.setHeader("Content-Type", mimeFor(req.query.file));
  res.setHeader("X-Kind", kindOf(req.query.file));
  res.send(describeError(Number(req.query.code)));
});

app.get("/b", (req, res) => {
  res.setHeader("X-Detail", describePath(req.query.file));
  res.send(storedName(req.query.id));
});

app.listen(3000);
