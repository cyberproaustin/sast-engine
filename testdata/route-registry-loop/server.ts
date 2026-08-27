import Fastify from "fastify";
import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import endpoints from "./endpoints.ts";

// A path held in a local constant. The registration states an address; that the address
// is spelled once above and used here does not make it less of an address.
const HEALTH_PATH = "/healthz";

// The collection this loop walks is decided at runtime, so nothing about it is knowable
// here. It must stay ONE route with an unresolved path -- expanding it over whatever
// happened to be nearby would invent addresses the application does not answer at.
const dynamicNames: string[] = process.env.EXTRA_ENDPOINTS?.split(",") ?? [];

export function createApiServer(
  fastify: FastifyInstance,
  options: FastifyPluginOptions,
  done: (err?: Error) => void,
): void {
  for (const endpoint of endpoints) {
    if (endpoint.meta.requireCredential) {
      fastify.all("/" + endpoint.name, async (request, reply) => {
        return reply.send({ ok: true });
      });
    } else {
      fastify.all("/" + endpoint.name, { bodyLimit: 1024 }, async (request, reply) => {
        return reply.send({ ok: true });
      });
    }
  }

  for (const name of dynamicNames) {
    fastify.get("/x/" + name, async (request, reply) => {
      return reply.send({ ok: true });
    });
  }

  fastify.get(HEALTH_PATH, async (request, reply) => {
    return reply.send({ ok: true });
  });

  done();
}

export function createServer(): FastifyInstance {
  const fastify = Fastify();

  // A route registered THROUGH a plugin function: the registrations live in
  // `createApiServer`, one hop from this call, and the prefix belongs to them.
  fastify.register(createApiServer, { prefix: "/api" });

  // Registered directly on the server rather than through the plugin, so it carries no
  // prefix: the mount belongs to the registration, not to the file.
  fastify.get("/diag/ping", async (request, reply) => {
    return reply.send({ ok: true });
  });

  return fastify;
}
