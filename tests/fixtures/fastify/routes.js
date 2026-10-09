export default async function api(server) {
  server.get('/items/:id', {preHandler: requireAuth}, async (request, reply) => {
    return request.query.filter;
  });
  server.route({method: ['GET', 'POST'], url: '/search', handler: search});
}
function search(request, reply) { return request.body; }
function requireAuth(request, reply) { return true; }
