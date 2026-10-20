import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';

const GENERIC_RATE_LIMIT_MESSAGE = { message: 'Too many attempts, please try again later' };

// Normalizes the submitted email so case/whitespace variants land in the same bucket,
// and hashes it so raw addresses never sit in the limiter's in-memory keys.
const hashEmail = (email) =>
  crypto.createHash('sha256').update(String(email || '').trim().toLowerCase()).digest('hex');

// Cheap, generous, IP-only filter mounted ahead of the body parser on all /api/auth/*
// routes, so a flood of requests is rejected before the cost of parsing their bodies
// is paid. Kept high because it's keyed on IP alone - a shared egress address (office
// NAT, CI runner) shouldn't lock out everyone behind it. The real per-account budget
// lives in credentialLimiter/passwordResetLimiter below.
export const authPreParseLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: GENERIC_RATE_LIMIT_MESSAGE,
});

// Guards login/register: keyed on IP + hashed email so one IP can't spray many
// accounts and one account can't be sprayed from many IPs. Only failed attempts count
// (skipSuccessfulRequests) so a legitimate user who signs in correctly doesn't spend
// the same budget as an attacker guessing wrong.
export const credentialLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `${req.ip}:${hashEmail(req.body?.email)}`,
  message: GENERIC_RATE_LIMIT_MESSAGE,
});

// Guards /forgot-password. Same IP+hashed-email key and budget as credentialLimiter,
// but counts every request - that route always responds ~200 (even for emails that
// don't exist) to avoid leaking account existence, so skipSuccessfulRequests would
// silently disable its rate limit.
export const passwordResetLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}:${hashEmail(req.body?.email)}`,
  message: GENERIC_RATE_LIMIT_MESSAGE,
});

// Separate bucket for the Google OAuth routes, which aren't a credential-guessing
// surface and shouldn't share budget with the password-based routes above.
export const oauthLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: GENERIC_RATE_LIMIT_MESSAGE,
});

export default function authMiddleware(req, res, next) {
  // Get token from header
  const authHeader = req.header('Authorization');
  if (!authHeader) {
    return res.status(401).json({ message: 'No authorization token, access denied' });
  }

  // Expect Bearer <token>
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({ message: 'Token format is invalid, must be Bearer <token>' });
  }

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'devsecretjwtkeysuper12345');
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token is not valid or expired' });
  }
}
