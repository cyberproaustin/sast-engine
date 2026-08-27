import Fastify from "fastify";
import type { FastifyInstance, FastifyPluginOptions } from "fastify";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie";

// A directory this application serves. There is no handler to name and none is invented:
// what exists is the ADDRESS, and an operator auditing the surface has to see it.
const ASSETS = "assets";

export function createFileServer(
  fastify: FastifyInstance,
  options: FastifyPluginOptions,
  done: (err?: Error) => void,
): void {
  // Inside a plugin, so the prefix the plugin was registered under belongs to it too.
  fastify.register(fastifyStatic, {
    root: "thumbnails",
    prefix: "/thumbs/",
    decorateReply: false,
  });

  done();
}

export function createServer(): FastifyInstance {
  const fastify = Fastify();

  // The ordinary mount: a root that says what is served and a prefix that says where.
  fastify.register(fastifyStatic, {
    root: ASSETS,
    prefix: "/assets/",
    decorateReply: false,
  });

  // No prefix. This plugin's default is `/`, so the address is stated by the default
  // rather than by the source, and it is still an address.
  fastify.register(fastifyStatic, {
    root: "uploads",
    decorateReply: false,
  });

  // NOT a mount. The same plugin registered purely so that handlers may call
  // `reply.sendFile`, with a placeholder root and serving nothing -- counting it would
  // put the whole server on the surface at `/`.
  fastify.register(fastifyStatic, {
    root: "placeholder",
    serve: false,
  });

  // NOT a mount. A plugin whose package does not say it serves files, registered with
  // options that carry no root: nothing here is a file server, and a rule that keyed on
  // `register` alone would have made one up.
  fastify.register(fastifyCookie, {
    secret: process.env.COOKIE_SECRET,
  });

  // NOT a mount either. The package is right and the file server's signature is absent:
  // with no root there is no directory, and this frontend does not guess one.
  fastify.register(fastifyStatic, {
    prefix: "/nothing/",
  });

  fastify.register(createFileServer, { prefix: "/files" });

  fastify.get("/healthz", async (request, reply) => {
    return reply.send({ ok: true });
  });

  return fastify;
}
