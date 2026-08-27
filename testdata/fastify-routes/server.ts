import Fastify from "fastify";
import { exec } from "child_process";

import { registerAdmin } from "./admin-plugin.ts";

// `const fastify = Fastify()` is the same evidence `const app = express()` is: the
// factory came from the framework's own module, so what it made is a Fastify server and
// the routes registered on it are Fastify routes.
const fastify = Fastify({ logger: true });

// EXPECTED FINDING — a Fastify request reaches a shell. The value is read off
// `request.query`, which exists on Fastify's request and not on Express's by accident of
// spelling: labelling this route `express` seeded the wrong shape and happened to work,
// and the point of the label is that it should not have to.
fastify.get<{ Querystring: { host: string } }>("/diag/ping", async (request, reply) => {
  exec("ping -c 1 " + request.query.host);
  return reply.send({ ok: true });
});

// EXPECTED FINDING — the body of a Fastify request, which is a property and not a
// method call the way it is in some other frameworks.
fastify.post("/diag/trace", async (request, reply) => {
  exec("traceroute " + request.body.target);
  return reply.send({ ok: true });
});

fastify.register(registerAdmin);

export default fastify;
