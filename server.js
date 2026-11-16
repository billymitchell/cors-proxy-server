require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const morgan = require('morgan'); // For logging HTTP requests

const app = express();
const PORT = process.env.PORT || 3000; // Use environment variable for PORT or default to 3000

// Enable CORS
app.use(cors());

// Middleware to log HTTP requests
app.use(morgan('combined'));

// Middleware to parse JSON bodies
app.use(express.json());

// Authentication middleware
app.use((req, res, next) => {
  try {
    const accessToken = req.body?.accessToken;
    const VALID_TOKEN = process.env.ACCESS_TOKEN; // Load token from .env

    if (!accessToken) {
      // Log missing token error
      console.error('Access token is missing in the request body');
      return res.status(400).json({ error: 'Access token is required' });
    }

    if (accessToken !== VALID_TOKEN) {
      // Log unauthorized access attempt
      console.error('Unauthorized access attempt with invalid token');
      return res.status(403).json({ error: 'Unauthorized access' });
    }

    next();
  } catch (error) {
    // Log unexpected errors
    console.error('Error in authentication middleware:', error.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.use((req, res, next) => {
  const target = req.query.target;
  if (target === undefined || target === '') {
    return res.status(400).json({ error: 'Target query parameter is required' });
  }

  let url;
  try {
    if (typeof target === 'string') url = new URL(target);
  } catch {
    return res.status(400).json({ error: 'Target must be an HTTP or HTTPS URL' });
  }
  if (!url || !['http:', 'https:'].includes(url.protocol)) {
    return res.status(400).json({ error: 'Target must be an HTTP or HTTPS URL' });
  }

  req.proxyTarget = url.href;
  delete req.body.accessToken;
  next();
});

app.use(createProxyMiddleware({
  changeOrigin: true,
  router: (req) => req.proxyTarget,
  on: {
    proxyReq(proxyReq, req) {
      // The JSON parser inflates compressed bodies before the proxy rewrites them.
      proxyReq.removeHeader('Content-Encoding');
      fixRequestBody(proxyReq, req);
    },
    error(err, req, res) {
      console.error('Proxy error:', err.message);
      if (res.headersSent) {
        res.destroy(err);
        return;
      }
      res.status(500).json({ error: 'Proxy error occurred' });
    },
  },
}));

// Global error handler for unexpected errors
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'Invalid JSON body' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'JSON body is too large' });
  }
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`CORS Proxy Server running on http://localhost:${PORT}`);
});
