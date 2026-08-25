const https = require("https");
const express = require("express");
const cors = require("cors");
const axios = require("axios");

const app = express();

// POSITIVE. Any site on the internet can make credentialed requests as the signed-in
// user, because the origin is reflected back.
app.use(cors({ origin: true, credentials: true }));

// NEGATIVE. Credentials allowed, but only to a named origin.
app.use(cors({ origin: "https://app.example.com", credentials: true }));

// NEGATIVE. A wildcard origin with no credentials is how a public API is served.
app.use(cors({ origin: "*" }));

// POSITIVE. Accepts any certificate, so the connection authenticates nobody.
const agent = new https.Agent({ rejectUnauthorized: false });

// NEGATIVE.
const strictAgent = new https.Agent({ rejectUnauthorized: true });

app.get("/proxy", async (req, res) => {
  const upstream = await axios.get("https://api.example.com/status", { httpsAgent: agent });
  res.json(upstream.data);
});

app.get("/strict", async (req, res) => {
  const upstream = await axios.get("https://api.example.com/status", { httpsAgent: strictAgent });
  res.json(upstream.data);
});

module.exports = app;
