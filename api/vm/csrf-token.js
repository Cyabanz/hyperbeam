import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();

export default function handler(req, res) {
  // 1. Generate secret
  const secret = tokens.secretSync();
  // 2. Generate token
  const csrfToken = tokens.create(secret);

  // 3. Set secret as HttpOnly cookie
  // Determine if we are on localhost (development) or production (HTTPS)
  const host = req.headers.host || '';
  const isLocalhost = host.startsWith('localhost') || host.startsWith('127.0.0.1');
  const useSecure = !isLocalhost; // Secure only if NOT localhost

  res.setHeader("Set-Cookie", cookie.serialize("csrfSecret", secret, {
    httpOnly: true,
    secure: useSecure,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 // 1 hour
  }));

  // 4. Return token to client
  res.status(200).json({ csrfToken });
}
