// NEGATIVE, and the one that matters most -- `pages/` without `api/` is the other half
// of the same convention and holds React components. This file is shaped exactly like a
// route: a directory-derived path, a default export, a function. It is a page rendered
// in a browser, no caller can invoke it as an HTTP handler, and enumerating the 38 files
// like it in one real application would have buried the 54 that are real routes.

import React from "react";

export default function Dashboard() {
  return <main>
    <h1>Dashboard</h1>
  </main>;
}
