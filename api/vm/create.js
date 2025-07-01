import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();
const sessionStore = global.sessionStore || (global.sessionStore = {});

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  // CSRF protection
  const cookies = cookie.parse(req.headers.cookie || "");
  const secret = cookies.csrfSecret;
  const csrfToken = req.headers["x-csrf-token"];
  if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
    res.status(403).json({ error: "Invalid CSRF token" });
    return;
  }

  // Call Hyperbeam to create session
  const HB_API_KEY = process.env.HYPERBEAM_API_KEY;
  if (!HB_API_KEY) {
    res.status(500).json({ error: "Missing Hyperbeam API key" });
    return;
  }

  try {
    const hbRes = await fetch("https://engine.hyperbeam.com/v0/vm", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${HB_API_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({}),
    });
    if (!hbRes.ok) {
      const err = await hbRes.text();
      res.status(500).json({ error: "Failed to create Hyperbeam session", details: err });
      return;
    }
    const data = await hbRes.json();
    const sessionId = data.id;
    const now = Date.now();

    // Setup 4-min hard limit timer
    const limitTimer = setTimeout(() => terminateSession(sessionId), 4 * 60 * 1000);

    // Setup 30s inactivity timer
    let inactivityTimer = setTimeout(() => terminateSession(sessionId), 30 * 1000);

    // Store timers
    sessionStore[sessionId] = {
      limitTimer,
      inactivityTimer,
      lastActive: now,
    };

    res.status(200).json({ ...data, expiresAt: now + 4 * 60 * 1000 });
  } catch (err) {
    res.status(500).json({ error: "Exception creating session", details: err.message });
  }
}

// Helper for terminating session and cleaning up timers
async function terminateSession(sessionId) {
  const HB_API_KEY = process.env.HYPERBEAM_API_KEY;
  if (!sessionStore[sessionId] || !HB_API_KEY) return;
  try {
    await fetch(`https://engine.hyperbeam.com/v0/vm/${sessionId}/terminate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${HB_API_KEY}` },
    });
  } catch (e) {
    // Ignore error, session may already be terminated
  }
  clearTimeout(sessionStore[sessionId].limitTimer);
  clearTimeout(sessionStore[sessionId].inactivityTimer);
  delete sessionStore[sessionId];
}