import fastify from 'fastify';
import api from './routes.js';
const app = fastify();
app.register(api, {prefix: '/api'});
