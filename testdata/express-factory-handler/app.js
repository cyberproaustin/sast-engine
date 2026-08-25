const express = require("express");
const { login, ambiguous } = require("./login");

const app = express();

app.post("/rest/user/login", login());
app.get("/either", ambiguous(true));

module.exports = app;
