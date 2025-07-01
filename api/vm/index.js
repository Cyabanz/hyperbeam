import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();
const sessionStore = global.sessionStore || (global.sessionStore = {});

export default async function handler(req, res) {
  if (req.method === "POST") {
    const cookies = cookie.parse(req.headers.cookie || "");
    const secret = cookies.csrfSecret;
    const csrfToken = req.headers["x-csrf-token"];
    if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
      res.status(403).json({ error: "Invalid CSRF token" });
      return;
    }

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
      const sessionUrl = data.url;
      const now = Date.now();

      const limitTimer = setTimeout(() => terminateSession(sessionId), 4 * 60 * 1000);
      let inactivityTimer = setTimeout(() => terminateSession(sessionId), 30 * 1000);

      sessionStore[sessionId] = {
        limitTimer,
        inactivityTimer,
        lastActive: now,
      };

      res.status(200).json({
        id: sessionId,
        url: sessionUrl,
        expiresAt: now + 4 * 60 * 1000
      });
    } catch (err) {
      res.status(500).json({ error: "Exception creating session", details: err.message });
    }
  } else if (req.method === "PATCH") {
    let body;
    try {
      body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
    } catch {
      res.status(400).json({ error: "Invalid JSON body" });
      return;
    }
    const { sessionId } = body;
    const session = sessionStore[sessionId];
    if (!session) {
      res.status(404).json({ error: "Session not found or already terminated" });
      return;
    }

    clearTimeout(session.inactivityTimer);
    session.inactivityTimer = setTimeout(() => terminateSession(sessionId), 30 * 1000);
    session.lastActive = Date.now();
    res.status(200).json({ ok: true });
  } else if (req.method === "DELETE") {
    const cookies = cookie.parse(req.headers.cookie || "");
    const secret = cookies.csrfSecret;
    const csrfToken = req.headers["x-csrf-token"];
    if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
      res.status(403).json({ error: "Invalid CSRF token" });
      return;
    }
    let sessionId;
    try {
      const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
      sessionId = body.sessionId;
    } catch {
      res.status(400).json({ error: "Invalid JSON body" });
      return;
    }
    if (!sessionId) {
      res.status(400).json({ error: "Missing sessionId" });
      return;
    }
    const HB_API_KEY = process.env.HYPERBEAM_API_KEY;
    if (!HB_API_KEY) {
      res.status(500).json({ error: "Missing Hyperbeam API key" });
      return;
    }

    try {
      const hbRes = await fetch(`https://engine.hyperbeam.com/v0/vm/${sessionId}/terminate`, {
        method: "POST",
        headers: { Authorization: `Bearer ${HB_API_KEY}` },
      });

      if (sessionStore[sessionId]) {
        clearTimeout(sessionStore[sessionId].limitTimer);
        clearTimeout(sessionStore[sessionId].inactivityTimer);
        delete sessionStore[sessionId];
      }

      if (hbRes.ok) {
        res.status(200).json({ ok: true });
        return;
      }
      if (hbRes.status === 404) {
        res.status(200).json({ ok: true, note: "Session already terminated or not found (404 from Hyperbeam)." });
        return;
      }
      const text = await hbRes.text();
      res.status(500).json({ error: "Failed to terminate Hyperbeam session", details: text });
    } catch (err) {
      res.status(500).json({ error: "API crashed", details: err.message });
    }
  } else {
    res.status(405).json({ error: "Method not allowed" });
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