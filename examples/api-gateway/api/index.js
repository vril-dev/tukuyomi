const express = require('express');

const app = express();
app.use(express.json({ limit: '1mb' }));

app.get('/v1/health', (_req, res) => {
  res.json({ ok: true, service: 'api-gateway-example' });
});

app.get('/v1/products', (_req, res) => {
  res.json({
    items: [
      { id: 1, name: 'starter-plan' },
      { id: 2, name: 'pro-plan' }
    ]
  });
});

app.get('/v1/whoami', (req, res) => {
  res.json({
    host: req.get('host') || '',
    x_forwarded_host: req.get('x-forwarded-host') || '',
    x_forwarded_proto: req.get('x-forwarded-proto') || '',
    x_protected_host: req.get('x-protected-host') || ''
  });
});

app.post('/v1/auth/login', (req, res) => {
  const username = req.body?.username || 'unknown';
  res.json({
    token: `demo-token-for-${username}`,
    issued_at: new Date().toISOString()
  });
});

app.use((_req, res) => {
  res.status(404).json({ error: 'not found' });
});

app.listen(8080, () => {
  console.log('api-gateway example listening on :8080');
});
