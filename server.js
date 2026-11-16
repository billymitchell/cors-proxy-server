require('dotenv').config();
const { timingSafeEqual } = require('node:crypto');
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
const morgan = require('morgan');

const app = express();
const port = process.env.PORT || 3000;
const accessToken = process.env.ACCESS_TOKEN;
const methods = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'];

const rules = JSON.parse(process.env.PROXY_RULES || '[]').map((rule) => {
  const url = new URL(rule.url);
  const browserOrigins = rule.browserOrigins ?? [];
  const querySecrets = rule.querySecrets ?? {};
  if (
    !['http:', 'https:'].includes(url.protocol) ||
    url.username || url.password || url.search || url.hash ||
    !Array.isArray(rule.methods) || !rule.methods.length ||
    !rule.methods.every((method) => methods.includes(method)) ||
    !Array.isArray(browserOrigins) ||
    !browserOrigins.every((origin) => /^https?:\/\//.test(origin) && new URL(origin).origin === origin) ||
    Object.values(querySecrets).some((name) => typeof name !== 'string' || !process.env[name])
  ) {
    throw new Error('Invalid PROXY_RULES entry or missing query secret environment variable');
  }
  return { url, methods: rule.methods, browserOrigins, querySecrets };
});

const browserOrigins = new Set(rules.flatMap((rule) => rule.browserOrigins));
app.use(morgan(':method :status :response-time ms'));
app.use(cors({
  origin: (origin, callback) => callback(null, browserOrigins.has(origin)),
  methods,
}));

function hasValidToken(req) {
  const value = req.get('Authorization');
  if (!accessToken || !value?.startsWith('Bearer ')) return false;
  const provided = Buffer.from(value.slice('Bearer '.length));
  const expected = Buffer.from(accessToken);
  return provided.length === expected.length && timingSafeEqual(provided, expected);
}

app.use((req, res, next) => {
  if (req.path !== '/') return res.sendStatus(404);

  let target;
  try {
    if (typeof req.query.target !== 'string') throw new TypeError();
    target = new URL(req.query.target);
  } catch {
    return res.status(400).json({ error: 'A valid target URL is required' });
  }

  const rule = rules.find((rule) =>
    !target.username && !target.password && !target.hash &&
    target.protocol === rule.url.protocol &&
    target.origin === rule.url.origin &&
    target.pathname === rule.url.pathname &&
    rule.methods.includes(req.method)
  );
  if (!rule) return res.status(403).json({ error: 'Target or method is not allowed' });

  const origin = req.get('Origin');
  if (origin && !rule.browserOrigins.includes(origin)) {
    res.removeHeader('Access-Control-Allow-Origin');
    return res.status(403).json({ error: 'Origin is not allowed for this target' });
  }
  if (!origin && !hasValidToken(req)) {
    return res.status(401).json({ error: 'A valid bearer token is required' });
  }

  for (const [parameter, envName] of Object.entries(rule.querySecrets)) {
    target.searchParams.set(parameter, process.env[envName]);
  }
  req.proxyTarget = target;
  next();
});

app.use(createProxyMiddleware({
  changeOrigin: true,
  proxyTimeout: 15000,
  router: (req) => req.proxyTarget.origin,
  pathRewrite: (_path, req) => req.proxyTarget.pathname + req.proxyTarget.search,
  on: {
    proxyReq(proxyReq) {
      proxyReq.removeHeader('Authorization');
      proxyReq.removeHeader('Cookie');
      proxyReq.removeHeader('Origin');
    },
    proxyRes(proxyRes, req, res) {
      for (const header of Object.keys(proxyRes.headers)) {
        if (header.startsWith('access-control-') || header === 'set-cookie') {
          delete proxyRes.headers[header];
        }
      }
      if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
        proxyRes.resume();
        res.status(502).json({ error: 'Upstream redirects are not supported' });
      }
    },
    error(err, req, res) {
      console.error('Upstream request failed:', err.code || err.name);
      if (res.headersSent) return res.destroy(err);
      res.status(502).json({ error: 'Upstream request failed' });
    },
  },
}));

const server = app.listen(port, () => {
  console.log(`CORS Proxy Server running on http://localhost:${server.address().port}`);
});
