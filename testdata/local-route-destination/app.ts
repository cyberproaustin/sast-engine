import axios from "axios";
import express from "express";

const app = express();

app.get("/local", (req, res) => {
  const segment = String(req.query.segment);
  window.open(`/Resource/${segment}`, "_blank");
  axios.get(`/Resource/${segment}`);
  res.redirect(`/Resource/${segment}`);
});

// A network-path reference replaces the authority even though the program wrote it.
app.get("/network-path", (req, res) => {
  const host = String(req.query.networkHost);
  window.open(`//${host}/resource`, "_blank");
  axios.get(`//${host}/resource`);
  res.redirect(`//${host}/resource`);
});

// Browser URL parsers normalize the backslash to the same authority-changing shape.
app.get("/backslash-path", (req, res) => {
  const host = String(req.query.backslashHost);
  window.open(`/\\${host}/resource`, "_blank");
  axios.get(`/\\${host}/resource`);
  res.redirect(`/\\${host}/resource`);
});

// The direct contrast: no relative-reference reasoning is needed for an absolute URL.
app.get("/absolute", (req, res) => {
  const host = String(req.query.absoluteHost);
  window.open(`https://${host}/resource`, "_blank");
  res.send("opened");
});
