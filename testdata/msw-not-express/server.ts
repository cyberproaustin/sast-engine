// A Fastify registration on a receiver the checker cannot type. It IS a route: it
// answers requests, and dropping it would trade one wrong number for another. What the
// engine still gets wrong here is the LABEL -- `models=express+nestjs` calls it express
// -- and that is a separate defect from claiming a mock is a route.
export function register(fastify) {
  fastify.get("/status", async (request, reply) => {
    return reply.send({ up: true });
  });
}
