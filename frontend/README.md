# Adaptive Security Suite - Modern Frontend

A production-ready React frontend for the Adaptive Security Suite with real-time monitoring, beautiful UI, and comprehensive security features.

## 🎨 Features

### ✨ User Interface
- **Modern Design**: Clean, professional interface with Tailwind CSS
- **Responsive**: Works perfectly on desktop, tablet, and mobile
- **Animations**: Smooth transitions with Framer Motion
- **Dark Mode Ready**: Easy to implement dark theme
- **Accessibility**: WCAG 2.1 compliant components

### 🔐 Security Features
- **Multi-Factor Authentication**: TOTP setup with QR codes
- **Device Management**: View and manage trusted devices
- **Risk Assessment**: Real-time risk score visualization
- **Threat Monitoring**: Live threat detection dashboard
- **Audit Logs**: Complete security event history

### 📊 Dashboard Components
- **Real-Time Charts**: Live threat activity with Recharts
- **Key Metrics**: Total threats, blocked attempts, active sessions
- **Threat Distribution**: Pie charts for attack type analysis
- **Recent Events**: Latest security incidents with status
- **System Health**: ML models, encryption, API status

### 🚀 Performance
- **Vite Build**: Lightning-fast development and builds
- **Code Splitting**: Automatic route-based splitting
- **Lazy Loading**: Components load on demand
- **Optimized Assets**: Minified and compressed
- **Service Worker Ready**: PWA support available

## 📦 Tech Stack

### Core
- **React 18**: Modern React with hooks
- **React Router 6**: Client-side routing
- **Vite**: Next-generation frontend tooling
- **Tailwind CSS**: Utility-first CSS framework

### State Management
- **Zustand**: Lightweight state management
- **React Query** (optional): Server state management

### UI Components
- **Framer Motion**: Animation library
- **Recharts**: Chart library for data visualization
- **Lucide React**: Beautiful icon library
- **React Hot Toast**: Toast notifications

### API Integration
- **Axios**: HTTP client with interceptors
- **Auto Token Refresh**: Seamless JWT handling
- **Error Handling**: Centralized error management

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ and npm/yarn
- Backend API running on http://localhost:5000

### Installation

```bash
cd frontend
npm install
```

### Development

```bash
npm run dev
```

Opens at http://localhost:3000

### Build for Production

```bash
npm run build
```

Outputs to `../static/dist` for Flask integration

### Preview Production Build

```bash
npm run preview
```

## 📁 Project Structure

```
frontend/
├── src/
│   ├── components/          # Reusable components
│   │   ├── Layout/          # Layout components
│   │   │   ├── DashboardLayout.jsx
│   │   │   ├── Sidebar.jsx
│   │   │   └── Header.jsx
│   │   ├── Common/          # Common UI components
│   │   │   ├── Button.jsx
│   │   │   ├── Input.jsx
│   │   │   └── Modal.jsx
│   │   └── Charts/          # Chart components
│   │       ├── ThreatChart.jsx
│   │       └── MetricsChart.jsx
│   ├── pages/               # Page components
│   │   ├── LoginPage.jsx
│   │   ├── RegisterPage.jsx
│   │   ├── MFASetupPage.jsx
│   │   ├── DashboardPage.jsx
│   │   ├── ThreatMonitorPage.jsx
│   │   ├── DevicesPage.jsx
│   │   ├── SecuritySettingsPage.jsx
│   │   └── AdminPage.jsx
│   ├── services/            # API services
│   │   ├── api.js           # Axios instance
│   │   ├── authService.js   # Authentication
│   │   ├── threatService.js # Threat detection
│   │   └── deviceService.js # Device management
│   ├── store/               # State management
│   │   ├── authStore.js     # Auth state
│   │   └── dashboardStore.js # Dashboard state
│   ├── hooks/               # Custom hooks
│   │   ├── useAuth.js
│   │   ├── useThreat.js
│   │   └── useWebSocket.js
│   ├── utils/               # Utility functions
│   │   ├── formatters.js
│   │   ├── validators.js
│   │   └── constants.js
│   ├── App.jsx              # Main app component
│   ├── main.jsx             # Entry point
│   └── index.css            # Global styles
├── public/                  # Static assets
├── index.html               # HTML template
├── vite.config.js           # Vite configuration
├── tailwind.config.js       # Tailwind configuration
├── package.json             # Dependencies
└── README.md                # This file
```

## 🔌 API Integration

### Authentication Flow

```javascript
// Login
POST /api/auth/login
{
  "username": "alice",
  "password": "SecurePass123!"
}

// Response
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "mfa_required": false
}

// MFA Verification (if required)
POST /api/mfa/verify-login
{
  "username": "alice",
  "code": "123456"
}
```

### Dashboard Data

```javascript
// Get system status
GET /api/suite/status

// Response
{
  "is_running": true,
  "uptime": "2 days, 3:45:12",
  "metrics": {
    "total_threats_detected": 1250,
    "total_policies_enforced": 987,
    "total_telemetry_processed": 50000
  }
}
```

### Real-Time Updates

```javascript
// WebSocket connection (optional)
const ws = new WebSocket('ws://localhost:5000/ws')

ws.onmessage = (event) => {
  const data = JSON.parse(event.data)
  // Update dashboard in real-time
}
```

## 🎨 Customization

### Colors

Edit `tailwind.config.js`:

```javascript
theme: {
  extend: {
    colors: {
      primary: {
        500: '#3b82f6',  // Your brand color
        600: '#2563eb',
      }
    }
  }
}
```

### Logo

Replace in `LoginPage.jsx`:

```jsx
<Shield className="w-8 h-8 text-white" />
// Replace with your logo component or image
```

### Charts

Customize in `DashboardPage.jsx`:

```jsx
<AreaChart data={threatData}>
  {/* Modify colors, gradients, axes */}
</AreaChart>
```

## 📱 Pages Overview

### 1. Login Page
- **Route**: `/login`
- **Features**:
  - Username/password authentication
  - MFA code entry
  - Password visibility toggle
  - Animated transitions
  - Error handling

### 2. Dashboard Page
- **Route**: `/`
- **Features**:
  - 4 key metric cards
  - Threat activity timeline chart
  - Threat distribution pie chart
  - Recent threats list
  - System status indicators

### 3. Threat Monitor Page
- **Route**: `/threats`
- **Features**:
  - Real-time threat feed
  - Filter by severity/type
  - Detailed threat information
  - MITRE ATT&CK mapping
  - Export capabilities

### 4. Devices Page
- **Route**: `/devices`
- **Features**:
  - List all user devices
  - Device fingerprint details
  - Trust/revoke actions
  - Login history per device
  - Risk assessment

### 5. Security Settings Page
- **Route**: `/settings`
- **Features**:
  - MFA management
  - Password change
  - Security preferences
  - Notification settings
  - API key management

### 6. Admin Page
- **Route**: `/admin`
- **Features**:
  - User management
  - Key rotation controls
  - System configuration
  - Audit logs
  - Performance metrics

## 🔒 Security Considerations

### Token Storage
- Tokens stored in localStorage with expiration
- Auto-refresh before expiration
- Secure token transmission (HTTPS only)

### XSS Protection
- React automatically escapes content
- Sanitize user inputs
- Content Security Policy headers

### CSRF Protection
- SameSite cookie attribute
- CSRF tokens for state-changing requests

### API Security
- Bearer token authentication
- Rate limiting on frontend
- Input validation before submission

## 🧪 Testing

### Unit Tests

```bash
npm test
```

### E2E Tests

```bash
npm run test:e2e
```

### Component Tests

```bash
npm run test:components
```

## 📈 Performance Optimization

### Code Splitting

```javascript
// Lazy load pages
const DashboardPage = lazy(() => import('./pages/DashboardPage'))
```

### Image Optimization

```javascript
// Use WebP format with fallback
<picture>
  <source srcset="image.webp" type="image/webp" />
  <img src="image.jpg" alt="Description" />
</picture>
```

### Caching Strategy

```javascript
// Cache API responses
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5 * 60 * 1000, // 5 minutes
      cacheTime: 10 * 60 * 1000, // 10 minutes
    }
  }
})
```

## 🌐 Deployment

### Production Build

```bash
npm run build
```

### Serve with Flask

The build output goes to `../static/dist`, which Flask serves automatically.

### Environment Variables

Create `.env`:

```bash
VITE_API_URL=https://api.yourdomain.com
VITE_WS_URL=wss://api.yourdomain.com/ws
VITE_ENV=production
```

### NGINX Configuration

```nginx
server {
  listen 443 ssl;
  server_name yourdomain.com;

  location / {
    root /path/to/static/dist;
    try_files $uri $uri/ /index.html;
  }

  location /api {
    proxy_pass http://localhost:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
  }
}
```

## 🐛 Troubleshooting

### Issue: API calls failing

**Solution**: Check CORS configuration and API URL in vite.config.js

### Issue: Build errors

**Solution**: Clear node_modules and reinstall
```bash
rm -rf node_modules package-lock.json
npm install
```

### Issue: Styles not loading

**Solution**: Rebuild Tailwind
```bash
npx tailwindcss -i ./src/index.css -o ./dist/output.css
```

## 📚 Resources

- [React Documentation](https://react.dev)
- [Vite Guide](https://vitejs.dev/guide/)
- [Tailwind CSS Docs](https://tailwindcss.com/docs)
- [Framer Motion](https://www.framer.com/motion/)
- [Recharts Examples](https://recharts.org/en-US/examples)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add AmazingFeature'`)
4. Push to branch (`git push origin feature/AmazingFeature`)
5. Open Pull Request

## 📝 License

This project is part of the Adaptive Security Suite.

---

**Built with ❤️ for enterprise security**
