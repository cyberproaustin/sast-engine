import express from "express";
import { exec } from "child_process";

const app = express();

// Named handler rather than an inline arrow. A frontend that only recognizes
// function literals at the registration site loses this entry point entirely.
app.get("/lookup", handleLookup);

async function handleLookup(req, res) {
  // Taint survives `await` and a method call on the tainted value itself.
  const raw = await normalize(req.query.host);
  const host = raw.trim();
  exec(`dig ${host}`); // EXPECTED FINDING
  res.send("ok");
}

async function normalize(value: string): Promise<string> {
  return value.toLowerCase();
}

// Promise continuation: the taint is in the receiver, and the sink is inside a
// callback the engine has to connect to it.
app.get("/chain", (req, res) => {
  loadTarget(req.query.target).then((resolved) => {
    exec("ping -c 1 " + resolved); // EXPECTED FINDING
  });
  res.send("ok");
});

async function loadTarget(value: string): Promise<string> {
  return value;
}

// Higher-order collection method: taint flows from the array into the element
// parameter of the callback.
app.get("/batch", (req, res) => {
  const hosts = req.query.hosts as string[];
  hosts.forEach((entry) => {
    exec(`ping -c 1 ${entry}`); // EXPECTED FINDING
  });
  res.send("ok");
});

app.listen(3000);
