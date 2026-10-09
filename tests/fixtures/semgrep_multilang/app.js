const app = require('fastify')();
app.post('/js/run', (req, reply) => execute(req.body.command));
function execute(command) { return eval(command); }
