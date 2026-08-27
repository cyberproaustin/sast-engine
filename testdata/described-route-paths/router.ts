// A route DESCRIBED rather than registered, with the path written every way the
// applications that use this shape actually write it.
//
// The frontend recognised this table and matched 109 of one application's 208
// descriptions. The 99 it dropped were not a different shape: 39 spell the router's own
// mount point as `path: ''`, 39 name a constant, and 21 build one from a constant.

import { getFeature, listFeatures, toggleOff, archive, root, validate } from "./handlers.ts";
import { register } from "./registrar.ts";

const PATH = "/:projectId/features";
const PATH_FEATURE = `${PATH}/:featureName`;
const PATH_ENV = `${PATH_FEATURE}/environments/:environment`;

// The mount point of the router this table belongs to. Express answers it at the mount,
// and a truthiness test on the path was rejecting it.
register({
  method: "get",
  path: "",
  handler: root,
});

// A literal, which is the only case that ever worked.
register({
  method: "get",
  path: "/health",
  handler: listFeatures,
});

// A constant declared at the top of this file.
register({
  method: "get",
  path: PATH_ENV,
  handler: getFeature,
});

// A constant built from constants, two hops from a literal.
register({
  method: "post",
  path: `${PATH_ENV}/off`,
  handler: toggleOff,
});

// A path this file cannot read: the mode is decided by the caller of the constructor,
// so the address genuinely depends on something not written here. The route still
// exists, and it says which expression stood in the way rather than claiming `*`.
const prefix = process.env.MODE === "global" ? "" : "/:projectId/context";

register({
  method: "delete",
  path: `${prefix}/:contextField`,
  handler: archive,
});

// NEGATIVE — a description with no handler is not a registration. This is the shape an
// HTTP CLIENT is configured with, and the tree is full of them.
export const outboundRequest = {
  method: "post",
  path: "/v1/telemetry",
  body: { seen: true },
};

// NEGATIVE — a handler that resolves to nothing. The description names a function this
// program does not contain, so there is nothing for a route to point at.
export const brokenRoute = {
  method: "get",
  path: "/never",
  handler: (globalThis as Record<string, unknown>).missingHandler,
};

export { validate };
