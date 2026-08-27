// A regex is a validation only when its accepted LANGUAGE excludes the syntax the sink
// interprets, and its failed result is the path that leaves.
//
// These handlers keep the value, pattern and sink identical around each boundary. That
// matters because every unsafe variant still looks like careful validation when read by
// position: the discriminator is full anchoring, the pattern's possible characters, and
// which branch reaches sendFile.
import express from "express";

const app = express();
const ICON_ROOT = "/srv/icons";

app.get("/safe-match/:path", (req, res) => {
  const path = req.params.path;
  // NEGATIVE. Every accepted value is one basename with one fixed dot, and failure
  // returns. Neither a path separator nor `..` can reach sendFile.
  if (!path.match(/^[0-9a-f-]+\.png$/)) return res.status(400).send("invalid icon");
  return res.sendFile(path, { root: ICON_ROOT });
});

app.get("/safe-test/:path", (req, res) => {
  const path = req.params.path;
  // NEGATIVE. RegExp.test spells the same proof with the pattern as the receiver.
  if (!/^[0-9a-f-]+\.png$/.test(path)) return res.status(400).send("invalid icon");
  return res.sendFile(path, { root: ICON_ROOT });
});

app.get("/substring/:path", (req, res) => {
  const path = req.params.path;
  // POSITIVE. `../../deadbeef.png` contains the allowed substring; neither end of the
  // input is constrained.
  if (!path.match(/[0-9a-f-]+\.png/)) return res.status(400).send("invalid icon");
  return res.sendFile(path, { root: ICON_ROOT });
});

app.get("/success-returns/:path", (req, res) => {
  const path = req.params.path;
  // POSITIVE. The pattern is safe and the polarity is backwards: safe names leave,
  // while traversal is precisely what falls through to the sink.
  if (path.match(/^[0-9a-f-]+\.png$/)) return res.status(400).send("already present");
  return res.sendFile(path, { root: ICON_ROOT });
});

app.get("/failure-continues/:path", (req, res) => {
  const path = req.params.path;
  // POSITIVE. Writing a rejection is not enforcement when both branches reconverge.
  if (!path.match(/^[0-9a-f-]+\.png$/)) res.status(400).send("invalid icon");
  return res.sendFile(path, { root: ICON_ROOT });
});

app.get("/unproved/:path", (req, res) => {
  const path = req.params.path;
  // POSITIVE. The backreference is outside the parser's proved language, and this
  // pattern genuinely admits traversal: `../../.png` repeats `../` twice.
  if (!path.match(/^([a-z./]+)\1\.png$/)) return res.status(400).send("invalid icon");
  return res.sendFile(path, { root: ICON_ROOT });
});

export default app;
