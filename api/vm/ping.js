const sessionStore = global.sessionStore || (global.sessionStore = {});

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ error: "Method not allowed" });
    return;
  }
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

  // Reset inactivity timer
  clearTimeout(session.inactivityTimer);
  session.inactivityTimer = setTimeout(() => terminateSession(sessionId), 30 * 1000);
  session.lastActive = Date.now();

  res.status(200).json({ ok: true });
}

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