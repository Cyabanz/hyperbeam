import Tokens from "csrf";
import cookie from "cookie";

const tokens = new Tokens();

export default function handler(req, res) {
  const secret = tokens.secretSync();
  const token = tokens.create(secret);

  res.setHeader(
    "Set-Cookie",
    cookie.serialize("csrfSecret", secret, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24,
      secure: process.env.NODE_ENV === "production",
    })
  );

  res.status(200).json({ csrfToken: token });
}