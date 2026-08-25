import express from "express";
import { execFile } from "child_process";
import { runPing, runLookup } from "./exec-helper";

const app = express();

// EXPECTED FINDING 1 — tainted request data crosses a function and a module
// boundary before reaching a shell-interpreted command.
app.get("/ping", (req, res) => {
  const target = req.query.host;
  const output = runPing(target);
  res.send(output);
});

// EXPECTED FINDING 2 — encodeURIComponent is a URL-context encoder. It percent-encodes
// most shell syntax, which is why this is a weaker case than it looks, and it leaves
// ' ( ) ! * ~ alone -- enough to break out of a quoted argument. It is reported with the
// sanitizer recorded as considered-and-insufficient, which is the honest answer for a
// transform that addresses a different context.
app.get("/lookup", (req, res) => {
  const encoded = encodeURIComponent(req.query.domain);
  res.send(runLookup(encoded));
});

// EXPECTED CLEAN — execFile does not spawn a shell. Taint reaches the argument
// array, but only a tainted executable path is dangerous here.
app.get("/ping-safe", (req, res) => {
  execFile("ping", ["-c", "1", req.query.host]);
  res.send("ok");
});

// EXPECTED CLEAN — no untrusted input reaches the command, and none comes back out.
//
// This route used to report. `runPing` is shared with `/ping` above, which DOES pass
// caller data, and a tainted return was handed to every call site of the function rather
// than to the ones that had passed something -- so the output of `ping localhost` read as
// the caller's own text. A function that returns what it was GIVEN returns it only to the
// callers that gave it something.
app.get("/status", (req, res) => {
  res.send(runPing("localhost"));
});

// EXPECTED FINDING — the caller chooses which executable runs. Same judgement as the
// shell cases, different weakness: nothing is shell-interpreted, so this is CWE-73
// (external control of a file path), not CWE-78. They roll up to different Top 10
// categories.
app.get("/run", (req, res) => {
  execFile(req.query.bin, ["--version"]);
  res.send("started");
});

app.listen(3000);
