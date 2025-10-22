# 🚀 Quick Start Guide - Adaptive Security System

## Start the System in 3 Steps

### ✅ Step 1: Start Frontend
**Double-click:** `start_frontend.bat`

Or run in terminal:
```bash
cd frontend
npm install    # First time only (may take 3-5 minutes)
npm run dev
```

**Frontend will start on:** http://localhost:5173

---

### ✅ Step 2: Start Backend (In separate terminal)
```bash
python main.py
```

**Backend will start on:** http://localhost:5000

---

### ✅ Step 3: Access Dashboard

Open browser and go to:
- **Comprehensive Dashboard:** http://localhost:5000/comprehensive_dashboard
- **React Dashboard:** http://localhost:5173/dashboard (after login)
- **Login Page:** http://localhost:5173/login

---

## 🎯 Alternative: Start Everything at Once

**Double-click:** `start_system.bat`

This will:
1. ✅ Start Flask backend (port 5000)
2. ✅ Start React frontend (port 5173)
3. ✅ Open in separate windows

---

## 🌐 Available URLs

### Backend (Flask)
- **Main API:** http://localhost:5000
- **System Status:** http://localhost:5000/api/suite/status
- **Comprehensive Dashboard:** http://localhost:5000/comprehensive_dashboard

### Frontend (React)
- **Main App:** http://localhost:5173
- **Login:** http://localhost:5173/login
- **Dashboard:** http://localhost:5173/dashboard

---

## 🔑 Test Credentials

```
Username: admin
Password: Admin123!@#
```

**For MFA:** Use Google Authenticator or similar app to scan QR code

---

## 📊 Dashboard Features

Once logged in, you'll see **8 comprehensive tabs:**

1. **📊 Overview** - System health and real-time metrics
2. **🔐 Authentication** - MFA management and user access
3. **🤖 AI Detection** - PyTorch models and threat analysis
4. **🔄 Adaptive Learning** - Model evolution and drift detection
5. **🌐 Network Security** - SDN enforcement and VLANs
6. **📈 Analytics** - Performance insights
7. **✅ Compliance** - Security standards (NIST, OWASP, GDPR)
8. **⚙️ Settings** - System configuration

---

## 🛠️ Troubleshooting

### Frontend not starting?
```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules package-lock.json
npm install
npm run dev
```

### Backend not starting?
```bash
# Activate virtual environment (if exists)
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Run
python main.py
```

### Port already in use?
```bash
# Kill process on port 5173 (frontend)
netstat -ano | findstr :5173
taskkill /PID <PID> /F

# Kill process on port 5000 (backend)
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### CORS errors?
- Ensure backend is running BEFORE frontend
- Check Flask CORS configuration in main.py

---

## 📱 Mobile Access

Access from mobile device on same network:
1. Find your computer's IP: `ipconfig` (Windows) or `ifconfig` (Mac/Linux)
2. Access: `http://<YOUR_IP>:5173`

Example: `http://192.168.1.100:5173`

---

## 🎨 What You'll See

### Landing Page
- Modern gradient design
- System overview
- Quick start buttons

### Dashboard
- Real-time metrics updating every 5 seconds
- Interactive charts and graphs
- Color-coded threat levels
- System architecture visualization

### Authentication
- MFA setup with QR codes
- Security features overview
- Recent authentication events

### AI Detection
- 4 PyTorch models with live stats
- Threat detection by type
- MITRE ATT&CK coverage matrix

---

## 📞 Need Help?

- **Frontend Guide:** See `FRONTEND_GUIDE.md`
- **System Objectives:** See `SYSTEM_OBJECTIVES_VERIFICATION.md`
- **Dataset Downloads:** See `DATASETS_DOWNLOAD_GUIDE.md`
- **Process Workflow:** See `PROCESS_WORKFLOW.md`

---

## ⚡ Pro Tips

1. **Keep both terminals open** - backend and frontend need to run simultaneously
2. **Use Chrome DevTools** (F12) to see API calls and errors
3. **Check browser console** for frontend errors
4. **Check terminal** for backend errors
5. **Refresh page** (Ctrl+R) if data not updating

---

**Ready to go!** 🚀

Just run:
```bash
start_system.bat
```

Or start frontend and backend separately in two terminals.

---

**System Version:** 1.0.0
**Last Updated:** January 2025
