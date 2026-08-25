const https = require("https");
const tls = require("tls");

// POSITIVE. Asking for a version with known breaks, specifically.
const legacy = new https.Agent({ secureProtocol: "TLSv1_method" });

// POSITIVE. Accepting one as a floor.
const lenient = tls.connect({ host: "peer.internal", minVersion: "TLSv1" });

// NEGATIVE.
const current = new https.Agent({ secureProtocol: "TLSv1_3_method" });

// NEGATIVE.
const strict = tls.connect({ host: "peer.internal", minVersion: "TLSv1.2" });

module.exports = { legacy, lenient, current, strict };
