/**
 * A method name is not the identity of the object receiving it.
 *
 * Node's streaming crypto objects and ORM models all expose `update`, but only the ORM
 * operation selects a shared record. The four crypto constructors below cover the Node
 * receiver families that produced two false CWE-639 findings in umami; the final route
 * holds the recall side by making a real record update with the same bare method name.
 */
import express from "express";
import { createCipheriv, createDecipheriv, createHash, createHmac } from "crypto";

const app = express();

function requireAuth(req, res, next): void {
  req.user = { id: "u1" };
  next();
}

class AccountModel {
  async update(id: string) {
    return { id };
  }
}

const accounts = new AccountModel();

app.post("/crypto", requireAuth, async (req, res) => {
  if (!req.user) {
    res.status(401).send();
    return;
  }
  const key = req.app.locals.cryptoKey;
  const iv = req.app.locals.cryptoIv;

  // EXPECTED CLEAN. This is the chained spelling reported in umami at crypto.ts:49.
  const hash = createHash("sha256").update(req.body.value).digest("hex");

  // EXPECTED CLEAN. Stored first, so receiver provenance has to survive assignment.
  const hmac = createHmac("sha256", key);
  hmac.update(req.body.value);

  // EXPECTED CLEAN. Encryption writes bytes into a streaming cipher, not a record.
  const cipher = createCipheriv("aes-256-cbc", key, iv);
  const encrypted = cipher.update(req.body.value);

  // EXPECTED CLEAN. This is the assigned decipher spelling reported at crypto.ts:45.
  const decipher = createDecipheriv("aes-256-cbc", key, iv);
  const decrypted = decipher.update(req.body.value);

  res.json({ hash, hmac: hmac.digest("hex"), encrypted, decrypted });
});

app.post("/accounts", requireAuth, async (req, res) => {
  if (!req.user) {
    res.status(401).send();
    return;
  }
  // EXPECTED FINDING. The caller chooses the model identifier and no ownership check
  // relates it to the authenticated actor. Excluding crypto receivers must not exclude
  // the ORM operation that gives the record-selector channel its recall.
  await accounts.update(req.body.accountId);
  res.json({ ok: true });
});

app.listen(3000);
