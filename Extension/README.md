# 🛡️ AI Phishing Detection Extension

A comprehensive Chrome extension with AI-powered phishing detection, real-time URL analysis, and a robust backend system for storing user data and flagged URLs.

## ✨ Features

### 🔐 **Authentication System**
- **User Registration & Login**: Secure JWT-based authentication
- **User Profiles**: Store user credentials and preferences
- **Session Management**: Persistent login across browser sessions

### 🎛️ **Extension Controls**
- **Enable/Disable Extension**: Toggle phishing protection on/off
- **Download Protection**: Block suspicious file downloads
- **Hover Detection**: Real-time URL analysis on hover
- **Notifications**: Desktop alerts for phishing detection

### 🔍 **Real-Time URL Analysis**
- **Hover Detection**: Analyzes URLs when hovering over links
- **ANN Model Integration**: AI-powered phishing detection
- **Instant Results**: Shows prediction and confidence level
- **URL Flagging**: Mark suspicious URLs for review

### 📊 **Statistics Dashboard**
- **Global Statistics**: Community-wide phishing detection data
- **User Statistics**: Personal scanning history and results
- **Interactive Charts**: Visual representation of data
- **Recent Activity**: Real-time activity feed

### 🛡️ **Security Features**
- **Download Protection**: Blocks dangerous file types
- **URL Validation**: Checks URLs before navigation
- **Phishing Warnings**: Alerts for dangerous websites
- **Context Menu**: Right-click options for URL analysis

## 🏗️ Architecture

### **Frontend (Chrome Extension)**
- **Manifest V3**: Modern Chrome extension architecture
- **Service Worker**: Background processing and state management
- **Content Scripts**: Page injection for hover detection
- **Popup Interface**: User-friendly control panel

### **Backend (Flask API)**
- **RESTful API**: Clean, scalable endpoint design
- **SQLite Database**: Lightweight data storage
- **JWT Authentication**: Secure user sessions
- **AI Model Integration**: Machine learning predictions

### **Database Schema**
```sql
-- Users table
users (id, username, email, password_hash, created_at, last_login, is_active)

-- Flagged URLs
flagged_urls (id, user_id, url, prediction, probability, flagged_at, notes)

-- URL Scans
url_scans (id, user_id, url, prediction, probability, scanned_at)

-- Extension Settings
extension_settings (id, user_id, extension_enabled, download_protection, hover_detection, notifications_enabled)

-- Global Statistics
global_statistics (id, total_urls_scanned, total_phishing_detected, total_safe_urls, total_suspicious_urls, total_users, last_updated)
```

## 🚀 Installation

### **Prerequisites**
- Python 3.8+
- Chrome/Chromium browser
- Git

### **Backend Setup**
```bash
# Clone repository
git clone <repository-url>
cd phishing-extension

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
cd backend
pip install -r requirements.txt

# Initialize database
python app.py
```

### **Extension Setup**
1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `phishing-extension` folder
4. The extension icon should appear in your toolbar

### **Configuration**
1. Click the extension icon to open the popup
2. Register a new account or login with existing credentials
3. Configure extension settings according to your preferences

## 📱 Usage

### **Basic Operation**
1. **Login**: Authenticate with your account
2. **Enable Extension**: Toggle the main switch to activate protection
3. **Browse Safely**: The extension automatically analyzes URLs on hover
4. **View Statistics**: Check your personal and global statistics

### **Hover Detection**
- Hover over any link or URL-containing element
- Wait 500ms for analysis to complete
- View prediction result and confidence level
- Flag suspicious URLs for review

### **Download Protection**
- Automatically scans downloaded files
- Blocks dangerous file types (.exe, .bat, etc.)
- Shows warnings for suspicious downloads
- User can override protection if needed

### **Statistics Dashboard**
- **Global Statistics**: Community-wide data and trends
- **User Statistics**: Personal scanning history
- **Interactive Charts**: Visual data representation
- **Recent Activity**: Real-time activity feed

## 🔧 API Endpoints

### **Authentication**
- `POST /register` - User registration
- `POST /login` - User authentication

### **URL Analysis**
- `POST /predict_url` - Analyze URL for phishing
- `POST /flag_url` - Flag suspicious URL

### **Statistics**
- `GET /get_global_stats` - Global community statistics
- `GET /get_user_stats` - User-specific statistics

### **Extension Settings**
- `GET /get_extension_settings` - Retrieve user settings
- `POST /update_extension_settings` - Update user settings

### **Health Check**
- `GET /health` - Backend status and model information

## 🧪 Testing

### **Backend Testing**
```bash
cd backend
python test_backend.py
```

### **Extension Testing**
1. Load the extension in Chrome
2. Navigate to various websites
3. Test hover detection on different links
4. Verify download protection functionality
5. Check statistics dashboard

## 🔒 Security Features

### **Data Protection**
- **Password Hashing**: Secure bcrypt-based password storage
- **JWT Tokens**: Stateless authentication with expiration
- **Input Validation**: Sanitized user inputs
- **CORS Protection**: Controlled cross-origin requests

### **Privacy**
- **Local Storage**: User preferences stored locally
- **Anonymous Statistics**: Global data without personal information
- **User Control**: Full control over data and settings

## 🎨 UI/UX Features

### **Modern Design**
- **Dark Theme**: Easy on the eyes
- **Glassmorphism**: Modern visual effects
- **Responsive Layout**: Works on all screen sizes
- **Smooth Animations**: Professional user experience

### **Accessibility**
- **High Contrast**: Clear visual hierarchy
- **Keyboard Navigation**: Full keyboard support
- **Screen Reader**: Compatible with assistive technologies
- **Color Blindness**: Accessible color schemes

## 🚧 Troubleshooting

### **Common Issues**

#### **Extension Not Loading**
- Check Chrome extension permissions
- Verify manifest.json syntax
- Clear browser cache and reload

#### **Backend Connection Issues**
- Ensure Flask server is running
- Check CORS settings
- Verify API endpoint URLs

#### **Hover Detection Not Working**
- Check if extension is enabled
- Verify hover detection is turned on
- Refresh the webpage

#### **Authentication Problems**
- Clear extension storage
- Re-register account
- Check backend server status

### **Debug Mode**
Enable Chrome DevTools for the extension:
1. Right-click extension icon
2. Select "Inspect popup"
3. Check console for error messages

## 🔮 Future Enhancements

### **Planned Features**
- **Machine Learning**: Improved AI model training
- **Community Features**: User reporting and sharing
- **Mobile App**: Cross-platform protection
- **API Integration**: Third-party security services

### **Performance Improvements**
- **Caching**: Faster URL analysis
- **Background Processing**: Non-blocking operations
- **Database Optimization**: Improved query performance

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the API documentation

## 🙏 Acknowledgments

- Chrome Extension Development Team
- Flask Framework Community
- Machine Learning Community
- Open Source Contributors

---

**⚠️ Disclaimer**: This extension is for educational and security purposes. Always use additional security measures and exercise caution when browsing the web. 