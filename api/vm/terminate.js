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

  // Terminate session
  try {
    const hbRes = await fetch(`https://engine.hyperbeam.com/v0/vm/${sessionId}/terminate`, {
      method: "POST",
      headers: { Authorization: `Bearer ${HB_API_KEY}` },
    });

    // Clean up timers
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
}