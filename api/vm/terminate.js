    const hbRes = await fetch(`https://engine.hyperbeam.com/v0/vm/${sessionId}/terminate`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${HB_API_KEY}`,
        "Content-Type": "application/json"
      }
    });

    const text = await hbRes.text();
    if (!hbRes.ok) {
      console.error("Hyperbeam API terminate error:", hbRes.status, text);
      return res.status(500).json({ error: "Failed to terminate Hyperbeam session", details: text });
    }
