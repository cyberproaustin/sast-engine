const axios = require("axios");
const express = require("express");

const app = express();
const users = {};

app.post("/enroll", (req, res) => {
  // POSITIVE. A password gets rotated after it leaks. A national identity number does
  // not, and a log is copied to more places than anyone tracks.
  console.log("enrolling", req.body.nationalId);

  // POSITIVE, and a different weakness: where it goes after leaving this process is not
  // this process's decision any more.
  axios.post("https://analytics.example.com/events", { dob: req.body.dateOfBirth });

  // POSITIVE. The caller decides what this account may do.
  const user = users[req.body.email] || {};
  user.role = req.body.role;

  res.json({ ok: true });
});

app.post("/enroll-safe", (req, res) => {
  // NEGATIVE. What is logged is that an enrolment happened, not who it was about.
  console.log("enrolling", req.body.email !== undefined);

  // NEGATIVE. The role is chosen by the application, not by the caller.
  const user = users[req.body.email] || {};
  user.role = "member";

  res.json({ ok: true });
});

module.exports = app;
