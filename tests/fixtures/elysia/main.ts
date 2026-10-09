import { Elysia } from 'elysia';
import { exec } from 'node:child_process';

new Elysia({ prefix: '/api' })
    .group('/v1', (app) => app
        .post('/run', ({ body }) => exec(body.command))
        .get('/files', ({ query }) => Bun.file(query.path))
    )
    .get('/safe', ({ query }) => fetch('https://example.com/health'))
    .listen(3000);
