
# 🛡️ Log Analyzer Pro

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub Stars](https://img.shields.io/github/stars/senku2006/log-analyzer)

Advanced server log analysis tool with real-time security threat detection.

![Dashboard Preview](docs/screenshots/dashboard.png)

## 📥 Installation

### Method 1: Pip Installation
```bash
# Clone the repository
git clone https://github.com/senku2006/log-analyzer.git

# Navigate to project directory
cd log-analyzer

# Install dependencies
pip install -r requirements.txt
```

### Method 2: Docker (Recommended for Production)
```bash
docker build -t log-analyzer .
docker run -p 8501:8501 log-analyzer
```

## ⚙️ Configuration

1. Create config file from sample:
```bash
cp config_sample.py config.py
```

2. Edit `config.py` with your settings:
```python
# Email Settings
EMAIL = {
    'user': 'your_email@gmail.com',
    'password': 'your_app_password'  # Use app password for Gmail
}

# Alert Thresholds
THRESHOLDS = {
    'failed_logins': 5,      # Failed login attempts
    'sql_injection': True,   # Detect SQLi
    'xss': True,            # Detect XSS
    'request_threshold': 1000 # Requests/min
}
```

## 🖥️ Usage

### Command Line:
```bash
python log_analyzer.py /path/to/logfile.log
```

### Web Dashboard (Streamlit):
```bash
streamlit run log_analyzer.py
```
Access dashboard at: `http://localhost:8501`

## 🔍 Key Features

- Real-time detection of:
  - SQL Injection (`SELECT * FROM users`)
  - XSS Attacks (`<script>alert()</script>`)
  - Directory Traversal (`../../etc/passwd`)
  - Brute Force Attacks

- Threat Severity Classification:
  - ⚠️ Warning (Low-risk patterns)
  - ❌ Critical (High-risk attacks)

## 📨 Alert System

Receive instant notifications via:
- Email (Gmail, SMTP)
- Slack Webhooks
- Telegram (Custom integration)

## 🛠️ Project Structure

```
log-analyzer/
├── log_analyzer.py      # Main application
├── config.py           # Configuration
├── requirements.txt    # Dependencies
├── docs/               # Documentation
│   └── screenshots/    # Screenshots
└── tests/              # Test cases
```

## 📊 Supported Log Formats

- Apache Common/Combined
- Nginx
- IIS
- Custom regex patterns

## ❓ Support

For issues or feature requests:
1. Open a [GitHub Issue](https://github.com/senku2006/log-analyzer/issues)
2. Email: senku2006@example.com

## 📜 License

This project is licensed under the [MIT License](LICENSE).
```

### Key Features of This README:
1. **Professional Formatting** with badges and emojis
2. **Multiple Installation Methods** (Pip/Docker)
3. **Detailed Configuration Guide**
4. **Visual Hierarchy** with clear sections
5. **Real-World Usage Examples**
6. **Alert System Documentation**
7. **Project Structure Overview**
8. **Support Information**

To use:
1. Copy this entire content
2. Create a new file named `README.md` in your project root
3. Paste and save
4. Replace placeholder images with your actual screenshots

This README follows GitHub best practices and includes all necessary information for users and contributors. Let me know if you'd like to add any specific features or sections!
