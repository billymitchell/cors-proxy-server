require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const cors = require('cors');
const { createProxyMiddleware } = require('http-proxy-middleware');
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
    const accessToken = req.body.accessToken; // Expecting the token in the request body
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

// Proxy middleware with dynamic target
app.use('*', createProxyMiddleware({
  changeOrigin: true,
  router: (req) => {
    try {
      // Extract the target server from the query parameter `target`
      const target = req.query.target;
      if (!target) {
        // Log missing target error
        console.error('Target query parameter is missing');
        throw new Error('Target query parameter is required');
      }
      return target;
    } catch (error) {
      // Log unexpected errors
      console.error('Error in proxy router:', error.message);
      throw error; // Re-throw the error to be handled by the proxy middleware
    }
  },
  onError: (err, req, res) => {
    // Handle proxy errors
    console.error('Proxy error:', err.message);
    res.status(500).json({ error: 'Proxy error occurred' });
  },
}));

// Global error handler for unexpected errors
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// Start the server
app.listen(PORT, () => {
  console.log(`CORS Proxy Server running on http://localhost:${PORT}`);
});
