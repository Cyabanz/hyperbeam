import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();

export default async function handler(req, res) {
  try {
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

    // Session ID from body
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

    const text = await hbRes.text();
    if (!hbRes.ok) {
      // Log the actual error for debugging
      console.error("Hyperbeam API terminate error:", hbRes.status, text);
      res.status(500).json({ error: "Failed to terminate Hyperbeam session", details: text });
      return;
    }

    res.status(200).json({ ok: true });
  } catch (err) {
    // Catch any unexpected errors and send a JSON error
    console.error("API /api/vm/terminate crashed:", err);
    res.status(500).json({ error: "API crashed", details: err.message });
  }
}
