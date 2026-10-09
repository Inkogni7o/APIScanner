import express from 'express';
import routes from './routes.js';
const app = express();
app.use('/api', requireAuth, routes);
app.use('/v2', routes);
function requireAuth(req, res, next) { next(); }
