import express = require('express');
import { createRouter } from '@/routes';
import { register } from './register';

const app = express();
app.use('/api', createRouter());
register(app);
