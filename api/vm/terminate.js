import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();

export default async function handler(req, res) {
  try {
    // Only allow POST
    if (req.method !== "POST") {
      res.status(405).json({ error: "Method not allowed" });
      return;
    }

    // Parse cookies to get CSRF secret
    const cookies = cookie.parse(req.headers.cookie || "");
    const secret = cookies.csrfSecret;
    const csrfToken = req.headers["x-csrf-token"];

    // Validate CSRF
    if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
      res.status(403).json({ error: "Invalid CSRF token" });
      return;
    }

    // Parse and check body
    let sessionId;
    try {
      const body = typeof req.body === "string" ? JSON.parse(req.body) : req.body;
      sessionId = body.sessionId;
    } catch (e) {
      res.status(400).json({ error: "Invalid JSON body" });
      return;
    }
    if (!sessionId) {
      res.status(400).json({ error: "Missing sessionId" });
      return;
    }

    // Hyperbeam API key
    const HB_API_KEY = process.env.HYPERBEAM_API_KEY;
    if (!HB_API_KEY) {
      res.status(500).json({ error: "Missing Hyperbeam API key" });
      return;
    }

    // Terminate the Hyperbeam session
    const hbRes = await fetch(`https://engine.hyperbeam.com/v0/vm/${sessionId}/terminate`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${HB_API_KEY}`,
        "Content-Type": "application/json"
      }
    });

    // Interpret the Hyperbeam response
    const text = await hbRes.text();
    if (hbRes.ok) {
      res.status(200).json({ ok: true });
      return;
    }
    // Treat 404 as idempotent "already terminated"
    if (hbRes.status === 404) {
      res.status(200).json({ ok: true, note: "Session already terminated or not found (404 from Hyperbeam)." });
      return;
    }
    // Other errors
    res.status(500).json({ error: "Failed to terminate Hyperbeam session", details: text });
  } catch (err) {
    // Unexpected errors
    res.status(500).json({ error: "API crashed", details: err.message });
  }
}
