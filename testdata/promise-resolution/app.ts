import express from "express";
import { exec } from "child_process";
import crypto from "crypto";
import fs from "fs";

const app = express();

// The shape this corpus exists for, taken from pdfjs's manifest check. The digest is
// computed inside a `stream.on("end", ...)` handler INSIDE the executor, handed to
// `resolve`, and compared two functions away. The executor returns nothing, so without
// the outward direction across the callback boundary the digest reaches nothing at all
// and the helper reads as a clean wrapper around a hash.
function calculateMD5(file: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("md5");
    const stream = fs.createReadStream(file);
    stream.on("error", (error) => reject(error));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

app.get("/verify", async (req, res) => {
  const md5 = await calculateMD5("./fixture.bin");
  if (md5 !== req.query.expected) { // EXPECTED FINDING: CWE-328
    res.send("mismatch");
    return;
  }
  res.send("ok");
});

// The same direction with caller data rather than a digest: whatever is handed to
// `resolve` is what `await` gives back, one frame down.
function normalizeHost(raw: string): Promise<string> {
  return new Promise((resolve) => {
    resolve(raw.trim());
  });
}

app.get("/ping", async (req, res) => {
  const host = await normalizeHost(req.query.host as string);
  exec(`ping -c 1 ${host}`); // EXPECTED FINDING: CWE-78
  res.send("ok");
});

// A continuation called from a function DECLARED inside the executor rather than from
// the executor itself. Both frontends lift a nested declaration to the top of the
// module, so "inside these braces" has to be recovered from the call graph.
function shout(value: string): Promise<string> {
  return new Promise((resolve) => {
    function done(text: string) {
      resolve(text);
    }
    done(value.toUpperCase());
  });
}

app.get("/shout", async (req, res) => {
  const out = await shout(req.query.value as string);
  exec(`logger ${out}`); // EXPECTED FINDING: CWE-78
  res.send("ok");
});

// NEGATIVE: rejection is not resolution. A rejected value arrives at a catch handler or
// as a thrown exception, and `await` on this promise gives back the constant. Claiming
// otherwise would be wrong about where the value went rather than merely incomplete.
function refuse(value: string): Promise<string> {
  return new Promise((resolve, reject) => {
    reject(value);
    resolve("fixed");
  });
}

app.get("/refuse", async (req, res) => {
  const out = await refuse(req.query.bad as string);
  exec(`echo ${out}`); // NO FINDING: what await gives back is the literal
  res.send("ok");
});

// NEGATIVE: a callback parameter of the same name is a DIFFERENT continuation. The inner
// `resolve` belongs to withRetry, and nothing handed to it completes the promise.
function shadowed(value: string): Promise<string> {
  return new Promise((resolve) => {
    withRetry(value, (resolve) => {
      resolve(value);
    });
    resolve("fixed");
  });
}

function withRetry(value: string, attempt: (v: string) => void) {
  attempt(value);
}

app.get("/shadowed", async (req, res) => {
  const out = await shadowed(req.query.value as string);
  exec(`echo ${out}`); // NO FINDING: the inner resolve is withRetry's, not the promise's
  res.send("ok");
});

app.listen(3000);
