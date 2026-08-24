// The same defect, in a file that does not run in production.
//
// A key written into a test is in the repository and in its history exactly as the reason
// says, and it is still not a production credential. Across sixteen repositories, 23 of 23
// hardcoded-secret findings were test fixtures and every one of them gated the build.
//
// So it is reported and never gates. What counts as a test file is an ecosystem convention,
// so the frontend decides it and the core only decides what it means.
import jwt from "jsonwebtoken";

export function tokenForTest() {
  return jwt.sign({ sub: "u1" }, "test-signing-key");
}
