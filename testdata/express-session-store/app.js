const express = require("express");
const session = require("express-session");

const app = express();

// POSITIVE, four times over, and every one of them is written one level down inside a
// `cookie` group -- which is why none of this was readable until the frontends started
// reading nested options. The secret is the worst of them: written into the source it is
// in every clone of the repository, and anybody holding the repository can mint a session
// for anybody.
app.use(
  session({
    secret: "keyboard cat",
    cookie: { secure: false, httpOnly: false, maxAge: 31536000000 },
  }),
);

// NEGATIVE. The secret comes from the environment, and the three attributes are set the
// way they should be.
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    cookie: { secure: true, httpOnly: true, maxAge: 900000 },
  }),
);

module.exports = app;
