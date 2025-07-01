import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();

export default function handler(req, res) {
  // 1. Generate secret
  const secret = tokens.secretSync();
  // 2. Generate token
  const csrfToken = tokens.create(secret);

  // 3. Set secret as HttpOnly cookie
  res.setHeader("Set-Cookie", cookie.serialize("csrfSecret", secret, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 // 1 hour
  }));

  // 4. Return token to client
  res.status(200).json({ csrfToken });
}
