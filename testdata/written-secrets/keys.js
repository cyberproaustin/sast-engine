// The sixth analysis kind, and the smallest: a value whose own shape is the defect. Not an
// argument, not a destination, not a flow -- simply there, and being there is all of it.

// POSITIVE. A credential in a connection string. It is in every clone of the repository,
// and a connection string is copied between environments far more often than rewritten.
const DATABASE_URL = "postgres://app_user:hunter2@db.internal:5432/production";

// POSITIVE. A private key block. Everybody who can read the repository can act as whatever
// this identifies, and revoking it means reissuing everything it signed.
const SIGNING_KEY = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIObtRo8tkUqoMjeHhsOh2ouPpXCgBcP0EDoeuazrxsK9oAoGCCqGSM49
-----END EC PRIVATE KEY-----`;

// POSITIVE. The provider-issued shapes. Each is a shape its issuer defined and nothing
// else has, which is why they can be matched with no context at all.
const AWS = "AKIAIOSFODNN7EXAMPLE";
const GH = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const SLACK = "xoxb-123456789012-234567890123-AbCdEfGhIjKlMnOpQrStUvWx";
const STRIPE = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const GOOGLE = "AIzaSyD-1234567890abcdefghijklmnopqrstu";
const NPM = "npm_abcdefghijklmnopqrstuvwxyz0123456789";

// POSITIVE. A signed token is not a key, but anybody holding the repository can present it
// until it expires or the key that signed it is retired.
const LICENCE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZXYifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// NEGATIVE, and the one thing that shares the shape of a credentialled URL without sharing
// its meaning: a format example. Superset ships eighteen of these and every one carries a
// bracket, a parenthesis or a space -- which a URL never does.
const FORMAT = "engine+driver://user:password@host[:port]/dbname[?key=value]";

// NEGATIVE. A URL with no credential in its authority.
const API = "https://api.example.com/v1/things?key=lookup";

// NEGATIVE. A public key is meant to be published; that is what makes it public.
const PUBLIC = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqR3LKD0hVj6VJqA0mAqB9pQ7VXBs
-----END PUBLIC KEY-----`;

// NEGATIVE. Test fixtures spell a Slack token this way, and seventy-three literals across
// sixteen production repositories are exactly this. The digit groups are what tell a real
// token from a placeholder that starts with the same four characters.
const FAKE_SLACK = "xoxb-oauth-bot-token";

// NEGATIVE. Nothing issues a key that looks like this, so nothing here claims one.
const NOT_A_KEY = "AKIA-not-a-real-identifier";

module.exports = { DATABASE_URL, SIGNING_KEY, AWS, GH, SLACK, STRIPE, GOOGLE, NPM, LICENCE, FORMAT, API, PUBLIC, FAKE_SLACK, NOT_A_KEY };
