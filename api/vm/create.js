import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }

  // Get secret from cookie
  const cookies = cookie.parse(req.headers.cookie || "");
  const secret = cookies.csrfSecret;
  const csrfToken = req.headers["x-csrf-token"];

  // Validate CSRF
  if (!secret || !csrfToken || !tokens.verify(secret, csrfToken)) {
    res.status(403).json({ error: "Invalid CSRF token" });
    return;
  }

  // --- Hyperbeam API Call ---
  // You MUST set your Hyperbeam API key in your Vercel project env vars
  const HB_API_KEY = process.env.HYPERBEAM_API_KEY;

  if (!HB_API_KEY) {
    res.status(500).json({ error: "Missing Hyperbeam API key" });
    return;
  }

  // Create the VM
  try {
    const hbRes = await fetch("https://engine.hyperbeam.com/v0/vm", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${HB_API_KEY}`
      },
      body: JSON.stringify({}) // Add options if needed
    });
    const data = await hbRes.json();
    res.status(200).json({
      embed_url: data.embed_url,
      session_id: data.session_id,
      admin_token: data.admin_token,
    });
  } catch (err) {
    res.status(500).json({ error: "Failed to create Hyperbeam session" });
  }
}
