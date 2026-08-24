const path = require("path");
const crypto = require("crypto");
const express = require("express");
const fileUpload = require("express-fileupload");

const app = express();
app.use(fileUpload());

const UPLOAD_DIR = "/srv/uploads";

// POSITIVE. The caller names the file, so the caller picks the extension.
app.post("/avatar", (req, res) => {
  const upload = req.files.avatar;
  upload.mv(path.join(UPLOAD_DIR, upload.name));
  res.json({ ok: true });
});

// NEGATIVE. The stored name is generated. Nothing the caller sent decides the type.
app.post("/avatar-generated", (req, res) => {
  const upload = req.files.avatar;
  const dest = path.join(UPLOAD_DIR, crypto.randomUUID() + ".png");
  upload.mv(dest);
  res.json({ ok: true });
});

// NEGATIVE. `.save()` on a record. Same method name, nothing else in common.
app.post("/notes", async (req, res) => {
  const note = new Note(req.body.title);
  await note.save();
  res.json({ ok: true });
});

// NEGATIVE. `.mv()` on something that is not an upload.
app.post("/reorder", (req, res) => {
  const playlist = loadPlaylist();
  playlist.mv(req.body.from, req.body.to);
  res.json({ ok: true });
});

module.exports = app;
