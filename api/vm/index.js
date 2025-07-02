import Tokens from "csrf";
import cookie from "cookie";
import NodeCache from "node-cache";

const tokens = new Tokens();

// Use node-cache for better serverless compatibility
// Sessions expire automatically after 5 minutes (cleanup buffer)
const sessionStore = new NodeCache({ 
  stdTTL: 300, // 5 minutes TTL
  checkperiod: 60, // Check for expired keys every minute
  useClones: false
});

// Rate limiting store - tracks sessions per IP
const rateLimitStore = new NodeCache({
  stdTTL: 300, // 5 minutes
  checkperiod: 60
});

// Constants
const MAX_SESSIONS_PER_IP = 2;
const SESSION_DURATION = 4 * 60 * 1000; // 4 minutes
const INACTIVITY_TIMEOUT = 30 * 1000; // 30 seconds

function getClientIP(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
         req.headers['x-real-ip'] || 
         req.connection?.remoteAddress || 
         req.socket?.remoteAddress ||
         'unknown';
}

function validateSessionId(sessionId) {
  return typeof sessionId === 'string' && sessionId.length > 0 && sessionId.length < 256;
}

async function terminateHyperbeamSession(sessionId) {
  const apiKey = process.env.HYPERBEAM_API_KEY;
  if (!apiKey) return false;
  
  try {
    const response = await fetch(`https://engine.hyperbeam.com/v0/vm/${sessionId}/terminate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    return response.ok || response.status === 404; // 404 means already terminated
  } catch (error) {
    console.error(`Failed to terminate Hyperbeam session ${sessionId}:`, error.message);
    return false;
  }
}

function cleanupSession(sessionId) {
  const session = sessionStore.get(sessionId);
  if (session) {
    // Clear timers
    if (session.limitTimer) clearTimeout(session.limitTimer);
    if (session.inactivityTimer) clearTimeout(session.inactivityTimer);
    
    // Update IP session count
    const ipSessions = rateLimitStore.get(session.clientIP) || [];
    const updatedSessions = ipSessions.filter(id => id !== sessionId);
    
    if (updatedSessions.length > 0) {
      rateLimitStore.set(session.clientIP, updatedSessions);
    } else {
      rateLimitStore.del(session.clientIP);
    }
    
    // Remove from session store
    sessionStore.del(sessionId);
  }
}

async function terminateSession(sessionId, reason = 'timeout') {
  console.log(`Terminating session ${sessionId} due to ${reason}`);
  
  await terminateHyperbeamSession(sessionId);
  cleanupSession(sessionId);
}

export default async function handler(req, res) {
  // Set security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  const clientIP = getClientIP(req);
  
  try {
    if (req.method === "POST") {
      // CSRF protection
      const cookies = cookie.parse(req.headers.cookie || "");
      const secret = cookies.csrfSecret;
      const csrfToken = req.headers["x-csrf-token"];
      
      if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
      }

      // Rate limiting check
      const ipSessions = rateLimitStore.get(clientIP) || [];
      if (ipSessions.length >= MAX_SESSIONS_PER_IP) {
        return res.status(429).json({ 
          error: `Rate limit exceeded. Maximum ${MAX_SESSIONS_PER_IP} sessions allowed per IP.`,
          retryAfter: 300
        });
      }

      // Validate API key
      const apiKey = process.env.HYPERBEAM_API_KEY;
      if (!apiKey) {
        return res.status(500).json({ error: "Service temporarily unavailable" });
      }

      // Create Hyperbeam session
      const hyperbeamResponse = await fetch("https://engine.hyperbeam.com/v0/vm", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          timeout: Math.floor(SESSION_DURATION / 1000) // Set timeout in seconds
        }),
      });

      if (!hyperbeamResponse.ok) {
        const errorText = await hyperbeamResponse.text();
        console.error('Hyperbeam API error:', errorText);
        return res.status(500).json({ 
          error: "Failed to create session",
          details: hyperbeamResponse.status === 429 ? "Service temporarily overloaded" : undefined
        });
      }

      const sessionData = await hyperbeamResponse.json();
      const sessionId = sessionData.id;
      
      if (!sessionId || !sessionData.url) {
        return res.status(500).json({ error: "Invalid session data received" });
      }

      const now = Date.now();
      const expiresAt = now + SESSION_DURATION;

      // Setup timers
      const limitTimer = setTimeout(() => terminateSession(sessionId, 'time_limit'), SESSION_DURATION);
      let inactivityTimer = setTimeout(() => terminateSession(sessionId, 'inactivity'), INACTIVITY_TIMEOUT);

      // Store session
      const session = {
        id: sessionId,
        clientIP,
        createdAt: now,
        lastActive: now,
        expiresAt,
        limitTimer,
        inactivityTimer,
        url: sessionData.url
      };
      
      sessionStore.set(sessionId, session);
      
      // Update rate limiting
      rateLimitStore.set(clientIP, [...ipSessions, sessionId]);

      return res.status(200).json({
        id: sessionId,
        url: sessionData.url,
        expiresAt
      });

    } else if (req.method === "PATCH") {
      // Activity ping to reset inactivity timer
      let body;
      try {
        body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
      } catch {
        return res.status(400).json({ error: "Invalid JSON body" });
      }

      const { sessionId } = body;
      
      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID" });
      }

      const session = sessionStore.get(sessionId);
      if (!session) {
        return res.status(404).json({ error: "Session not found or expired" });
      }

      // Verify session belongs to same IP (basic security check)
      if (session.clientIP !== clientIP) {
        return res.status(403).json({ error: "Access denied" });
      }

      // Reset inactivity timer
      if (session.inactivityTimer) {
        clearTimeout(session.inactivityTimer);
      }
      
      session.inactivityTimer = setTimeout(() => terminateSession(sessionId, 'inactivity'), INACTIVITY_TIMEOUT);
      session.lastActive = Date.now();
      
      sessionStore.set(sessionId, session);

      return res.status(200).json({ ok: true });

    } else if (req.method === "DELETE") {
      // Explicit session termination
      const cookies = cookie.parse(req.headers.cookie || "");
      const secret = cookies.csrfSecret;
      const csrfToken = req.headers["x-csrf-token"];
      
      if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
        return res.status(403).json({ error: "Invalid CSRF token" });
      }

      let sessionId;
      try {
        const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
        sessionId = body.sessionId;
      } catch {
        return res.status(400).json({ error: "Invalid JSON body" });
      }

      if (!validateSessionId(sessionId)) {
        return res.status(400).json({ error: "Invalid session ID" });
      }

      const session = sessionStore.get(sessionId);
      if (session && session.clientIP !== clientIP) {
        return res.status(403).json({ error: "Access denied" });
      }

      await terminateSession(sessionId, 'user_request');
      return res.status(200).json({ ok: true });

    } else {
      return res.status(405).json({ error: "Method not allowed" });
    }
    
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ 
      error: "Internal server error",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}