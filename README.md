# log-analyzer
Here's a **complete, detailed README.md file** for your Log Analyzer project with professional English explanations:

```markdown
# 🛡️ Advanced Log Analyzer

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

An advanced server log analysis tool with real-time security threat detection, geo-IP tracking, and alert systems.

![Dashboard Screenshot](docs/screenshots/dashboard.png)

## ✨ Key Features
- Supports Apache/Nginx/IIS log formats
- Detects SQLi, XSS, LFI, RCE attacks
- Real-time email/Slack alerts
- Interactive Streamlit dashboard
- Geo-IP visualization
- Login attempt monitoring

## 🚀 Installation

### Prerequisites
- Python 3.8+
- Git (optional)

### Method 1: Using Pip
```bash
# Clone the repository
git clone https://github.com/senku2006/log-analyzer.git
cd log-analyzer

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Using Docker (Recommended for Production)
```bash
docker build -t log-analyzer .
docker run -p 8501:8501 log-analyzer
```

## 🛠️ Configuration
1. Copy the sample config file:
   ```bash
   cp config_sample.py config.py
   ```
2. Edit `config.py` with your settings:
   ```python
   # Alert Settings
   EMAIL = {
       'user': 'your_email@gmail.com',
       'password': 'app_password'  # Use app password for Gmail
   }
   
   SLACK_WEBHOOK = "https://hooks.slack.com/services/..."
   ```

## 💻 Usage
```bash
# Run the analyzer
streamlit run log_analyzer/main.py

# Access the dashboard at:
http://localhost:8501
```

## 📊 Sample Log Format
The analyzer supports standard web server logs:
```
192.168.1.1 - - [01/Jan/2023:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234
```

## 🛡️ Threat Detection
Detects these attack patterns:
- SQL Injection: `SELECT * FROM users`
- XSS: `<script>alert()</script>`
- LFI: `../../etc/passwd`
- Brute Force: Multiple 401 errors

## 🌐 Geo-IP Tracking
Visualizes attacker locations on a world map using IP geolocation.

## 🔔 Alert Types
| Alert Type       | Trigger Condition          |
|------------------|----------------------------|
| High Traffic     | >1000 requests/min         |
| SQLi Attempt     | Detected SQL keywords      |
| XSS Attempt      | Detected script tags       |
| Failed Logins    | >5 failed attempts per IP  |

## 🤝 Contributing
1. Fork the repository
2. Create your feature branch:
   ```bash
   git checkout -b feature/amazing-feature
   ```
3. Commit your changes:
   ```bash
   git commit -m 'Add amazing feature'
   ```
4. Push to the branch:
   ```bash
   git push origin feature/amazing-feature
   ```
5. Open a pull request

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.

## 📧 Contact
Senku - [@senku2006](https://github.com/senku2006)
```

### Key Elements Explained:

1. **Badges**: Visual indicators for Python version and license
2. **Installation Options**: Both pip and Docker methods
3. **Configuration**: Clear steps for setting up alerts
4. **Usage**: Simple one-command startup
5. **Threat Detection**: Lists all detectable attack types
6. **Tables**: Organized alert conditions
7. **Contributing Guide**: Standard GitHub workflow
8. **Visual Elements**: Screenshot reference and badges

### Professional Touches:
- Uses standard GitHub markdown formatting
- Includes both CLI and Docker deployment options
- Clear section headers with emojis
- Table for alert conditions
- Badges for quick info scanning
- Contact information

This README follows best practices for open-source projects and provides all necessary information for users and contributors.
