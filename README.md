# 🚀 Secure Hyperbeam Session Demo

A secure, production-ready Hyperbeam session manager with rate limiting, session management, and enhanced security features. Optimized for deployment on Vercel.

## 🔧 Features

### ✅ **Implemented Improvements**
- **Rate Limiting**: Maximum 2 sessions per IP address
- **Session Management**: 4-minute maximum duration with 30-second inactivity timeout
- **Enhanced Security**: CSRF protection, input validation, and security headers
- **Vercel Optimized**: Serverless-compatible session storage using node-cache
- **Better Error Handling**: Comprehensive error messages and user feedback
- **Modern UI**: Improved user interface with real-time session status
- **Automatic Cleanup**: Proper session termination and resource cleanup

### 🛡️ **Security Features**
- CSRF token protection for state-changing operations
- IP-based session tracking and rate limiting
- Input validation for all API endpoints
- Security headers (XSS Protection, Content-Type Options, Frame Options)
- Session ownership validation
- Proper error handling without information leakage

### ⏱️ **Session Management**
- **Maximum Duration**: 4 minutes per session
- **Inactivity Timeout**: 30 seconds of inactivity
- **Rate Limiting**: 2 concurrent sessions per IP
- **Automatic Cleanup**: Sessions are terminated and cleaned up automatically
- **Real-time Updates**: Live timer and session status updates

## 🚀 Quick Start

### Prerequisites
- Node.js 14+ 
- A Hyperbeam API key ([Get one here](https://hyperbeam.com/))
- Vercel account (for deployment)

### Local Development

1. **Clone and install dependencies:**
   ```bash
   npm install
   ```

2. **Set up environment variables:**
   Create a `.env.local` file:
   ```bash
   HYPERBEAM_API_KEY=your_hyperbeam_api_key_here
   ```

3. **Run locally:**
   ```bash
   npx vercel dev
   ```

4. **Access the application:**
   Open http://localhost:3000

### Vercel Deployment

1. **Deploy to Vercel:**
   ```bash
   npx vercel --prod
   ```

2. **Set environment variables in Vercel:**
   ```bash
   npx vercel env add HYPERBEAM_API_KEY
   ```
   Enter your Hyperbeam API key when prompted.

3. **Redeploy to apply environment variables:**
   ```bash
   npx vercel --prod
   ```

## 📁 Project Structure

```
├── api/
│   └── vm/
│       ├── index.js       # Main API handler (POST, PATCH, DELETE)
│       └── csrf-token.js  # CSRF token generation
├── index.html             # Frontend interface
├── package.json           # Dependencies
├── vercel.json           # Vercel configuration
└── README.md             # This file
```

## 🔌 API Endpoints

### `POST /api/vm`
Creates a new Hyperbeam session.
- **Requires**: CSRF token
- **Rate Limited**: 2 sessions per IP
- **Returns**: Session ID, URL, and expiration time

### `PATCH /api/vm`
Sends activity ping to reset inactivity timer.
- **Body**: `{ "sessionId": "session_id" }`
- **Returns**: Success confirmation

### `DELETE /api/vm`
Terminates a session.
- **Requires**: CSRF token
- **Body**: `{ "sessionId": "session_id" }`
- **Returns**: Success confirmation

### `GET /api/vm/csrf-token`
Generates CSRF token and sets secure cookie.
- **Returns**: CSRF token for subsequent requests

## 🛡️ Security Improvements

### Before vs After

| Feature | Before | After |
|---------|--------|-------|
| **Session Storage** | Global memory (unreliable) | node-cache (serverless-safe) |
| **Rate Limiting** | ❌ None | ✅ 2 sessions per IP |
| **Input Validation** | ❌ Basic | ✅ Comprehensive |
| **Error Handling** | ❌ Exposes internals | ✅ Safe error messages |
| **Security Headers** | ❌ None | ✅ Full security headers |
| **Session Ownership** | ❌ No validation | ✅ IP-based validation |
| **Cleanup** | ❌ Memory leaks | ✅ Automatic cleanup |

### Security Headers Applied
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

## 📊 Rate Limiting Details

- **Limit**: 2 concurrent sessions per IP address
- **Window**: 5 minutes (sessions expire from rate limit tracking)
- **Response**: HTTP 429 with retry-after information
- **Bypass**: None (enforced at IP level)

## 🔧 Configuration

### Environment Variables
- `HYPERBEAM_API_KEY`: Your Hyperbeam API key (required)
- `NODE_ENV`: Set to "production" for production deployment

### Timing Configuration
You can modify these constants in `api/vm/index.js`:
```javascript
const MAX_SESSIONS_PER_IP = 2;           // Sessions per IP
const SESSION_DURATION = 4 * 60 * 1000;  // 4 minutes
const INACTIVITY_TIMEOUT = 30 * 1000;    // 30 seconds
```

## 🐛 Error Handling

The application handles various error scenarios:
- **Rate limiting exceeded**: Clear message with retry time
- **CSRF token issues**: Prompts to refresh page
- **Network errors**: Displays connection issues
- **Session expiration**: Automatic cleanup and notification
- **Invalid input**: Validation error messages

## 🎨 UI Features

- **Real-time timer**: Visual progress bar with color coding
- **Session info**: Live session details and countdown
- **Status messages**: Color-coded status updates
- **Rate limit notices**: Clear rate limiting feedback
- **Responsive design**: Works on desktop and mobile
- **Accessibility**: Proper semantic HTML and ARIA labels

## 📈 Performance

- **Serverless optimized**: Uses node-cache for efficient memory usage
- **Automatic cleanup**: Prevents memory leaks in serverless environment
- **Efficient timers**: Proper timer management and cleanup
- **Minimal dependencies**: Only essential packages included

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

## 🆘 Support

For issues with:
- **This application**: Open a GitHub issue
- **Hyperbeam API**: Contact Hyperbeam support
- **Vercel deployment**: Check Vercel documentation

---

**Note**: This is a demo application. For production use, consider additional security measures such as user authentication, database-backed session storage, and monitoring.