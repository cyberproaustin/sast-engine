const express = require("express");
const app = express();

function sendHttpError(res, msg) {
  if (msg.includes("BUSY")) {
    res.status(503).json({ status: "fail", msg });
  } else if (msg.toLowerCase().includes("not found")) {
    res.status(404).json({ status: "fail", msg });
  } else {
    res.status(403).json({ status: "fail", msg });
  }
}

app.get("/badge", async (_req, res) => {
  try {
    throw new Error("backend failed");
  } catch (error) {
    sendHttpError(res, error.message);
  }
});

export function duplicatedFixture() {
  const input = "https://user:password@example.com/path";
  const expected = "https://user:password@example.com/path";
  return input === expected;
}

module.exports = app;
