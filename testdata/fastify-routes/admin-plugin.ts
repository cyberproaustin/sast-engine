import type { FastifyInstance, FastifyPluginOptions } from "fastify";

// The path is a local constant and no registration in this file spells a literal, so
// nothing here LOOKS like a route: the receiver is the only evidence, and it is a
// parameter. Its declared type is what says the parameter holds a Fastify server --
// not its name, which is the mistake the framework label was making in the first place.
const PURGE_PATH = "/admin/purge";

export function registerAdmin(
  fastify: FastifyInstance,
  options: FastifyPluginOptions,
  done: (err?: Error) => void,
): void {
  fastify.get(PURGE_PATH, async (request, reply) => {
    return reply.send({ ok: true });
  });
  done();
}
