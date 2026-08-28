interface Config {
  signingKeyId?: string;
  signingKey?: string;
  idSigningKey?: string;
}

const config: Config = {};

// The generated key's identifier selects key material held elsewhere; it cannot sign.
config.signingKeyId = "medplum-generated-key";

// The near miss is key material in the same configuration namespace.
config.signingKey = "production-signing-material";

// An identifier word in another role does not earn the suffix exclusion.
config.idSigningKey = "identifier-signing-material";
