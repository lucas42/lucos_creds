import express from 'express';
import { middleware as authMiddleware } from './auth.js';

const app = express();
app.auth = authMiddleware;
const port = process.env.PORT || 3000;

app.use((req, res, next) => app.auth(req, res, next));

app.get('/', (req, res) => {
  res.send('Hello World!')
});

app.listen(port, () => {
  console.log(`UI listening on port ${port}`)
});