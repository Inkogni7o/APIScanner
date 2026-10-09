import { Router } from 'express';
import { exec } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { execute } from '../utils';

export function makeRoutes() {
    const router = Router();
    router.post('/run', (req, res) => {
        const command = req.body.command;
        execute(command);
    });
    router.get('/files/:name', async (req, res) => {
        const data = await readFile('/srv/files/' + req.params.name);
        res.send(data);
    });
    router.get('/safe', (req, res) => {
        exec('echo safe');
        res.send(req.query.q);
    });
    return router;
}
