import { Request, Response, Express } from 'express';

export function register(app: Express) {
    app.get('/proxy', async (req: Request, res: Response) => {
        const url = req.query.url;
        const result = await fetch(url);
        res.send(result);
    });
}
