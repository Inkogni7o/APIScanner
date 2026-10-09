import { Hono } from 'hono';
import { readFile } from 'node:fs/promises';

const files = new Hono();
files.get('/files/:name', async (c) => {
    return c.text(await readFile(c.req.param('name'), 'utf8'));
});

const app = new Hono().basePath('/api');
app.route('/v1', files);
app.get('/proxy', async (c) => fetch(c.req.query('url')));
