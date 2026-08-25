import express from "express";
import { csrfProtection, requireAuth } from "./middleware";
import { showProfile, updateProfile, updateEmail, changePassword } from "./handlers";

const app = express();

// Cookie sessions, which is what makes an anti-CSRF token mean anything here. On an API
// authenticated by a bearer header a token buys nothing, and half the programs in the
// world are that -- which is why "this route has no CSRF middleware" is not a finding and
// "this route has no CSRF middleware and its peers do" is.
app.use(express.urlencoded({ extended: false }));

app.get("/profile", requireAuth, showProfile);

app.post("/profile", requireAuth, csrfProtection, updateProfile);
app.post("/profile/email", requireAuth, csrfProtection, updateEmail);
app.post("/profile/avatar", requireAuth, csrfProtection, updateProfile);
app.post("/profile/timezone", requireAuth, csrfProtection, updateProfile);

// EXPECTED DEVIATION. Its peers carry the token check and this one does not, and the
// program has already declared by carrying it elsewhere that its routes are reached with
// a cookie. Nothing here is a pattern to match: the defect is what is absent.
app.post("/profile/password", requireAuth, changePassword);

app.listen(3000);
