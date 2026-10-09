import { Router } from 'express';
import { execute } from './utils.js';
const router = Router();
function show(req, res) { res.send(req.query.name); }
router.route('/users/:id').get(show).post((req, res) => { execute(req.body.command); });
export default router;
