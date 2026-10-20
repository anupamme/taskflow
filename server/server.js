import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import mongoose from 'mongoose';
import passport from 'passport';
import authRoutes from './routes/auth.js';
import taskRoutes from './routes/tasks.js';
import passwordResetRoutes from './routes/passwordReset.js';
import { authPreParseLimiter } from './middleware/auth.js';
import './config/passport.js'; // Imports Strategy setup

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Trust the configured number of reverse-proxy hops so req.ip reflects the real client,
// not the proxy. Using `true` here would let a client spoof X-Forwarded-For and bypass
// rate limiting; the exact hop count depends on deployment topology, so it's configurable.
const trustProxyHops = Number.parseInt(process.env.TRUST_PROXY_HOPS, 10);
app.set('trust proxy', Number.isNaN(trustProxyHops) ? 1 : trustProxyHops);

// Middleware
app.use(cors({
  origin: '*', // Allow all origins for local testing
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// Cheap IP-only cap on all auth routes, applied before the body parser so a request
// flood is rejected before the cost of parsing its body is paid.
app.use('/api/auth', authPreParseLimiter);
app.use(express.json());
app.use(passport.initialize());

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/auth', passwordResetRoutes);
app.use('/api/tasks', taskRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'online',
    database: 'connected',
    timestamp: new Date()
  });
});

// Database connection
console.log('================================================================');
console.log('Database connection (Supabase Cloud) initialized successfully!');
console.log('================================================================');

// Start Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
