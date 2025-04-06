import re
import streamlit as st
import pandas as pd
import yagmail
import requests
import json
from collections import Counter, defaultdict
from datetime import datetime
from multiprocessing import Pool
from functools import lru_cache
import matplotlib.pyplot as plt
import geopandas as gpd
from sklearn.ensemble import IsolationForest
from transformers import pipeline

# -------------------- الإعدادات الأساسية --------------------
EMAIL_USER = "your_email@gmail.com"
EMAIL_PASS = "your_app_password"
TO_EMAIL = "security_team@example.com"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXXXX/XXXXX/XXXXX"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_KEY"
ABUSEIPDB_API_KEY = "YOUR_ABUSEIPDB_KEY"

# -------------------- أنماط التهديدات الأمنية --------------------
SECURITY_PATTERNS = {
    "sql_injection": [
        r"\bselect\b.+?\bfrom\b",
        r"\bunion\b.+?\bselect\b",
        r"\bdrop\s+table\b",
        r"\binsert\s+into\b",
        r"\bdelete\s+from\b",
        r"\bupdate\b.+?\bset\b",
        r"\bexec\b",
        r"\bxp_cmdshell\b",
        r"--",
        r"/\*",
        r"\*/",
        r"'\s+or\s+'\d+'='\d+'"
    ],
    "xss": [
        r"<script>",
        r"javascript:",
        r"onerror=",
        r"onload=",
        r"eval\(",
        r"alert\(",
        r"document\.cookie",
        r"<iframe>",
        r"src=javascript:"
    ],
    "lfi": [
        r"\.\./",
        r"\.\.\\",
        r"etc/passwd",
        r"proc/self/environ"
    ],
    "rce": [
        r"system\(",
        r"exec\(",
        r"shell_exec\(",
        r"passthru\(",
        r"popen\("
    ]
}

# -------------------- أنماط تحليل السجلات --------------------
LOG_PATTERNS = {
    "apache": re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<time>.*?)\] "(?P<method>[A-Z]+) (?P<url>\S+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<size>\d+)'
    ),
    "nginx": re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<time>.*?)\] "(?P<method>[A-Z]+) (?P<url>\S+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<size>\d+)'
    ),
    "iis": re.compile(
        r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) - - \[(?P<time>.*?)\] "(?P<method>[A-Z]+) (?P<url>\S+) HTTP/\d\.\d" (?P<status>\d{3}) (?P<size>\d+)'
    )
}

# -------------------- القوائم السوداء والإعدادات --------------------
BLACKLISTED_IPS = {"192.168.1.100", "10.0.0.5"}
REQUEST_THRESHOLD = 1000
LOGIN_FAIL_THRESHOLD = 10
LOGIN_FAILS = defaultdict(int)

# -------------------- وظائف التحليل الجغرافي --------------------
@lru_cache(maxsize=1000)
def geoip_lookup(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "lat": data.get("lat"),
            "lon": data.get("lon")
        }
    except:
        return None

def check_ip_reputation(ip):
    try:
        response = requests.get(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            timeout=3
        )
        data = response.json()
        return {
            "abuse_score": data["data"]["abuseConfidenceScore"],
            "is_public": data["data"]["isPublic"],
            "is_tor": data["data"]["isTor"]
        }
    except:
        return None

# -------------------- وظائف تحليل السجلات --------------------
def parse_log_line(line, log_type):
    match = LOG_PATTERNS[log_type].match(line)
    if match:
        return match.groupdict()
    return None

def analyze_line(line, log_type):
    data = parse_log_line(line, log_type)
    if not data:
        return None

    result = {
        "ip": data['ip'],
        "url": data['url'],
        "status": data['status'],
        "time": data['time'],
        "threats": []
    }

    # تحليل التهديدات الأمنية
    for threat_type, patterns in SECURITY_PATTERNS.items():
        for pattern in patterns:
            try:
                if data['url'] and re.search(pattern, data['url'], re.IGNORECASE):
                    result["threats"].append(threat_type)
                    break
            except re.error:
                continue

    # معلومات جغرافية
    geo_info = geoip_lookup(data['ip'])
    if geo_info:
        result.update(geo_info)

    # سمعة IP
    reputation = check_ip_reputation(data['ip'])
    if reputation:
        result.update({"reputation": reputation})

    return result

def parallel_analyze(lines, log_type):
    with Pool(processes=4) as pool:
        results = pool.starmap(analyze_line, [(line, log_type) for line in lines])
    return [r for r in results if r is not None]

# -------------------- وظائف التنبيهات --------------------
def send_email_alert(subject, content, to=TO_EMAIL):
    try:
        yag = yagmail.SMTP(EMAIL_USER, EMAIL_PASS)
        yag.send(to=to, subject=subject, contents=content)
        print("✔️ Alert email sent.")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def send_slack_alert(message):
    try:
        payload = {"text": message}
        response = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=3)
        if response.status_code == 200:
            print("✔️ Alert sent to Slack.")
        else:
            print(f"❌ Failed to send Slack message. Status code: {response.status_code}")
    except Exception as e:
        print(f"❌ Error sending Slack alert: {e}")

def send_telegram_alert(message, chat_id):
    try:
        requests.post(
            f"https://api.telegram.org/botYOUR_BOT_TOKEN/sendMessage",
            json={"chat_id": chat_id, "text": message},
            timeout=3
        )
    except Exception as e:
        print(f"❌ Error sending Telegram alert: {e}")

# -------------------- واجهة المستخدم --------------------
st.set_page_config(page_title="Advanced Log Analyzer", layout="wide")
st.title("🛡️ Advanced Server Log Analyzer")

# علامات التبويب
tab1, tab2, tab3, tab4 = st.tabs(["Basic Analysis", "Security Threats", "Geo Analysis", "Settings"])

with tab1:
    st.header("Basic Log Analysis")
    log_type = st.selectbox("Select Log Type", ("apache", "nginx", "iis"))
    uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt"])

with tab2:
    st.header("Security Threat Detection")
    enable_threat_detection = st.checkbox("Enable Advanced Threat Detection", True)

with tab3:
    st.header("Geographical Analysis")
    show_geo = st.checkbox("Show Geographical Distribution", True)

with tab4:
    st.header("Settings")
    enable_email = st.checkbox("Enable Email Alerts")
    enable_slack = st.checkbox("Enable Slack Alerts")
    enable_telegram = st.checkbox("Enable Telegram Alerts")
    telegram_chat_id = st.text_input("Telegram Chat ID")

if uploaded_file:
    lines = uploaded_file.read().decode("utf-8", errors="ignore").splitlines()
    
    with st.spinner("Analyzing log entries..."):
        results = parallel_analyze(lines, log_type)
    
    if not results:
        st.error("No valid log entries found!")
        st.stop()

    # تحويل النتائج إلى DataFrame
    df = pd.DataFrame(results)
    
    # تحليل أساسي
    with tab1:
        st.subheader("Traffic Overview")
        col1, col2, col3 = st.columns(3)
        col1.metric("Total Requests", len(df))
        col2.metric("Unique IPs", df['ip'].nunique())
        col3.metric("Attack Attempts", df[df['threats'].apply(len) > 0].shape[0])
        
        st.subheader("Top IPs")
        top_ips = df['ip'].value_counts().head(10)
        st.bar_chart(top_ips)
        
        st.subheader("Status Code Distribution")
        status_counts = df['status'].value_counts()
        st.bar_chart(status_counts)
    
    # تحليل التهديدات الأمنية
    with tab2:
        if enable_threat_detection:
            threats = df[df['threats'].apply(len) > 0]
            if not threats.empty:
                st.subheader("Detected Threats")
                
                # تصنيف التهديدات
                threat_counts = defaultdict(int)
                for threat_list in threats['threats']:
                    for threat in threat_list:
                        threat_counts[threat] += 1
                
                st.bar_chart(pd.DataFrame.from_dict(threat_counts, orient='index', columns=['count']))
                
                # عرض التهديدات التفصيلية
                st.subheader("Threat Details")
                st.dataframe(threats)
                
                # إرسال تنبيهات
                if enable_email or enable_slack or enable_telegram:
                    alert_content = "🚨 Security Threats Detected:\n\n"
                    for threat_type, count in threat_counts.items():
                        alert_content += f"- {threat_type}: {count} attempts\n"
                    
                    if enable_email:
                        send_email_alert("Security Alert - Threat Detected", alert_content)
                    if enable_slack:
                        send_slack_alert(alert_content)
                    if enable_telegram and telegram_chat_id:
                        send_telegram_alert(alert_content, telegram_chat_id)
            else:
                st.success("No security threats detected!")
    
    # التحليل الجغرافي
    with tab3:
        if show_geo and 'country' in df.columns:
            countries = df['country'].value_counts()
            st.subheader("Requests by Country")
            st.bar_chart(countries.head(10))
            
            st.subheader("World Map")
            try:
                world = gpd.read_file(gpd.datasets.get_path('naturalearth_lowres'))
                merged = world.set_index('name').join(countries.rename('count'))
                
                fig, ax = plt.subplots(1, 1, figsize=(15, 10))
                merged.plot(column='count', ax=ax, legend=True,
                          missing_kwds={"color": "lightgrey"},
                          cmap='OrRd', scheme='quantiles')
                plt.title('Global Request Distribution')
                st.pyplot(fig)
            except Exception as e:
                st.warning(f"Could not display map: {e}")
    
    # إعدادات إضافية
    with tab4:
        st.subheader("Export Options")
        export_format = st.selectbox("Export Format", ["CSV", "JSON", "PDF"])
        
        if st.button("Export Report"):
            if export_format == "CSV":
                csv = df.to_csv(index=False)
                st.download_button("Download CSV", csv, "log_analysis.csv")
            elif export_format == "JSON":
                json_str = df.to_json(orient='records')
                st.download_button("Download JSON", json_str, "log_analysis.json")
            else:
                st.warning("PDF export requires additional libraries")

# -------------------- الميزات الإضافية --------------------
# نموذج التعلم الآلي لاكتشاف الشذوذ (اختياري)
@st.cache_resource
def load_anomaly_model():
    return IsolationForest(contamination=0.01)

# نموذج تصنيف النصوص (اختياري)
@st.cache_resource
def load_text_classifier():
    return pipeline("text-classification", model="distilbert-base-uncased")

# يمكنك إضافة المزيد من الوظائف حسب الحاجة
