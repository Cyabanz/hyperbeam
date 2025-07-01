import React, { useState } from "react";

export default function Home() {
  const [csrfToken, setCsrfToken] = useState("");
  const [session, setSession] = useState(null);
  const [terminateStatus, setTerminateStatus] = useState("");
  const [loading, setLoading] = useState(false);

  // Get CSRF token
  const getToken = async () => {
    setCsrfToken("");
    setSession(null);
    setTerminateStatus("");
    setLoading(true);
    const res = await fetch("/api/vm/csrf-token", { credentials: "include" });
    const data = await res.json();
    setCsrfToken(data.csrfToken);
    setLoading(false);
  };

  // Create Hyperbeam session
  const createSession = async () => {
    setLoading(true);
    setTerminateStatus("");
    setSession(null);
    const res = await fetch("/api/vm/create", {
      method: "POST",
      headers: {
        "x-csrf-token": csrfToken,
        "Content-Type": "application/json"
      },
      credentials: "include"
    });
    const data = await res.json();
    setSession(data);
    setLoading(false);
  };

  // Terminate Hyperbeam session
  const terminateSession = async () => {
    if (!session?.session_id) return;
    setTerminateStatus("Terminating session...");
    setLoading(true);
    try {
      const res = await fetch("/api/vm/terminate", {
        method: "POST",
        headers: {
          "x-csrf-token": csrfToken,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ sessionId: session.session_id }),
        credentials: "include"
      });
      let data;
      try {
        data = await res.json();
      } catch {
        data = { error: "Server error: response was not JSON." };
      }
      if (data.ok) {
        setTerminateStatus("Session terminated!");
        setSession(null);
      } else {
        setTerminateStatus("Failed to terminate: " + (data.error || "Unknown error") + (data.details ? "\n" + data.details : ""));
      }
    } catch (e) {
      setTerminateStatus("Network or server error: " + e.message);
    }
    setLoading(false);
  };

  return (
    <div style={{ maxWidth: 600, margin: "3em auto", fontFamily: "sans-serif" }}>
      <h1>Hyperbeam + CSRF Demo</h1>
      <button onClick={getToken} disabled={loading}>Get CSRF Token</button>
      <br />
      <pre>CSRF: {csrfToken ? csrfToken : "(none)"}</pre>
      <button onClick={createSession} disabled={!csrfToken || loading}>Create Hyperbeam Session</button>
      <br />
      {session && (
        <pre>
          Session: {JSON.stringify(session, null, 2)}
          {session.embed_url && (
            <>
              <br />
              <a href={session.embed_url} target="_blank" rel="noopener noreferrer">Open Hyperbeam</a>
            </>
          )}
        </pre>
      )}
      {session && (
        <button onClick={terminateSession} disabled={loading}>Terminate Hyperbeam Session</button>
      )}
      <pre>{terminateStatus}</pre>
    </div>
  );
}
