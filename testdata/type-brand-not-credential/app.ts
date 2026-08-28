import express from "express";

const app = express();
app.use(express.json());

app.post("/login", (req, res) => {
  // A real hardcoded credential: the caller's credential is compared with the text.
  if (req.body.password === "winter-is-coming") {
    res.send("welcome");
    return;
  }

  // A type brand: the call produces the standardized tag and the literal names the
  // expected runtime type. The same text used as a password above would still fire.
  if (Object.prototype.toString.call(req.body.password) === "[object String]") {
    res.send("wrong password type");
  }
});
