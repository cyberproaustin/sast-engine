// NEGATIVE -- a test module. It sits under `pages/api` and it default-exports a
// function, so nothing about its SHAPE distinguishes it from the route beside it. A
// route that exists only in a test is not part of the program that gets deployed, which
// is the program this enumerates.

import handler from "./health";

export default function run() {
  const res = { status: () => ({ json: () => undefined }) };
  handler({ method: "GET" } as never, res as never);
}
