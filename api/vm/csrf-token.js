const Tokens = require("csrf");
const cookie = require("cookie");

module.exports = async function handler(req, res) {
  try {
    // Set security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Only allow GET requests
    if (req.method !== 'GET') {
      return res.status(405).json({ error: 'Method not allowed' });
    }

    const tokens = new Tokens();
    const secret = tokens.secretSync();
    const token = tokens.create(secret);

    res.setHeader(
      "Set-Cookie",
      cookie.serialize("csrfSecret", secret, {
        httpOnly: true,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 60 * 24, // 24 hours
        secure: process.env.NODE_ENV === "production",
      })
    );

    res.status(200).json({ csrfToken: token });
  } catch (error) {
    console.error('CSRF token generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate CSRF token',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
};