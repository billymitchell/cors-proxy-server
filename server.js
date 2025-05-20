require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = 3000;

// Enable CORS
app.use(cors());

// Middleware to parse JSON bodies
app.use(express.json());

// Authentication middleware
app.use((req, res, next) => {
  const accessToken = req.body.accessToken; // Expecting the token in the request body
  const VALID_TOKEN = process.env.ACCESS_TOKEN; // Load token from .env

  if (accessToken !== VALID_TOKEN) {
    return res.status(403).json({ error: 'Unauthorized access' });
  }

  next();
});

// Proxy middleware with dynamic target
app.use('*', createProxyMiddleware({
  changeOrigin: true,
  router: (req) => {
    // Extract the target server from the query parameter `target`
    const target = req.query.target;
    if (!target) {
      throw new Error('Target query parameter is required');
    }
    return target;
  },
}));

app.listen(PORT, () => {
  console.log(`CORS Proxy Server running on http://localhost:${PORT}`);
});
