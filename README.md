# 🔒 Enhanced Malicious URL Detection System 2025

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-cybersecurity-red.svg)](https://github.com/cassielxyz/malicious-url-detector)

A comprehensive cybersecurity tool that uses advanced machine learning, IP analysis, and real-time threat intelligence to detect and classify malicious URLs with high accuracy.

## 📁 Project Structure

malicious-url-detector/
├── url_detector.py (86KB)           # 🚀 Main script
├── requirements.txt                 # 📦 Dependencies  
├── README.md                        # 📖 Documentation
├── .gitignore                       # 🚫 Git rules
├── maliciouslinks.csv               # 📊 Results log
├── organize.bat                     # 🔧 Organizer script
├── data/                           # 📂 Training datasets
│   ├── comprehensive_training.csv
│   ├── sample_dataset.csv
│   └── training_sample.csv
├── docs/                           # 📚 Documentation
│   └── additional_docs.md
├── scripts/                        # 🛠️ Utility scripts
│   ├── setup.py
│   └── test.py
├── logs/                           # 📋 Log files
│   └── debug.log
├── models/                         # 🤖 ML models
│   └── xgboost_model.json
├── notebooks/                      # 📓 Jupyter notebooks
│   └── malicious_url_analysis.ipynb
├── output/                         # 📤 Generated outputs
└── malicious links/                # 🦠 Known malicious URLs
    ├── banking_phishing.txt
    ├── ip_based_urls.txt
    ├── mixed_suspicious.txt
    ├── tech_impersonation.txt
    └── url_shorteners.txt



## 🎯 Key Features

- ✅ **8-Stage Analysis Pipeline** - Comprehensive URL evaluation
- ✅ **Advanced IP Detection** - Private/Public/Suspicious range analysis
- ✅ **8 Malware Types** - Phishing, Malware, Crypto scams, etc.
- ✅ **XGBoost ML Model** - 50+ features, 85%+ accuracy
- ✅ **VirusTotal Integration** - Real-time multi-engine scanning
- ✅ **SSL Certificate Validation** - Security verification
- ✅ **CSV Logging** - Comprehensive threat intelligence storage
- ✅ **Interactive CLI** - User-friendly command interface
..................................................
## 🚀 Installation & Setup

### **Step 1: Clone the Repository**

git clone https://github.com/cassielxyz/malicious-url-detector.git
cd malicious-url-detector


..................................................
### **Step 2: Create Virtual Environment**

**Windows:**
python -m venv venv
venv\Scripts\activate

.................................................

**Linux/Mac:**
python3 -m venv venv
source venv/bin/activate


................................................
### **Step 3: Install Dependencies**

pip install --upgrade pip
pip install -r requirements.txt

###############################################

**Required packages:**
- pandas
- numpy
- validators
- requests
- scikit-learn
- xgboost
##############################################




## 🖥️ How to Run the Program

### **Step 1: Start the Detector**

python url_detector.py

text

### **Step 2: Interactive Commands**

The system provides several commands:

🔗 Enter URL for complete comprehensive analysis: [your_url]

text

**Available Commands:**
- **URL Analysis** - Enter any URL (e.g., `http://suspicious-site.com`)
- **`stats`** - View detection statistics and trends
- **`types`** - Show supported malware types
- **`recent`** - Display recent malicious URLs found
- **`help`** - Show detailed help information
- **`quit`** - Exit the program

### **Step 3: Analysis Process**

When you enter a URL, the system performs:

1. **📋 URL Validation** - Format checking and normalization
2. **🌐 Internet Accessibility** - Connectivity and response testing
3. **🔒 SSL Certificate Verification** - Security certificate validation
4. **🤖 Machine Learning Analysis** - AI-powered threat detection
5. **🧑‍💻 VirusTotal Verification** - Multi-engine scanning
6. **🦠 Malware Type Classification** - Threat categorization
7. **⚖️ Final Verdict Calculation** - Risk score aggregation
8. **💾 Comprehensive Storage** - Data logging and statistics

### **Step 4: Understanding Results**

**Verdict Types:**
- ✅ **SAFE** - URL appears legitimate
- ❓ **QUESTIONABLE** - Minor suspicious indicators
- ⚠️ **SUSPICIOUS** - Multiple risk factors detected
- 🚨 **HIGH_RISK** - Significant threat indicators
- ☠️ **MALICIOUS** - Confirmed malicious URL

**Example Output:**
🏷️ FINAL VERDICT: ☠️ MALICIOUS

🦠 COMPREHENSIVE MALWARE CLASSIFICATION:
Type: PHISHING
Risk Level: HIGH
Confidence: 87.3%
Description: Credential stealing, fake login pages

🌐 IP ADDRESS ANALYSIS:
IP Address: 192.168.1.100
IP Type: PRIVATE_IP
IP Risk Score: 70/100

🤖 ADVANCED MACHINE LEARNING ANALYSIS:
Prediction: Malicious
Confidence: 89.2%
Malicious Probability: 89.2%

text

## 📊 Data Storage

### **Malicious URLs CSV**
All detected threats are logged in `maliciouslinks.csv` with:
- Timestamp and URL
- ML prediction confidence
- VirusTotal results  
- Malware type classification
- IP analysis details
- Risk scoring metrics

### **Statistics Dashboard**
Use the `stats` command to view:
- Total URLs analyzed
- Detection trends
- Malware type distribution
- IP-based threat percentage
- SSL certificate statistics

## 🎯 Usage Examples

### **Example 1: Analyze a Suspicious URL**
🔗 Enter URL: http://192.168.1.1/admin

text

### **Example 2: Check Statistics**
🔗 Enter URL: stats
📊 Complete Statistics:
Total stored: 15
IP-based threats: 8 (53.3%)
SSL secured: 40.0%
Malware types: {'PHISHING': 5, 'ADMIN_PANEL': 3}

text

### **Example 3: View Recent Threats**
🔗 Enter URL: recent
📋 Recent 5 Comprehensive Analysis Results:
🕒 2025-08-05 00:15:30 | 🌐🔓 http://192.168.1.100/login... | MALICIOUS | ADMIN_PANEL | TL:HIGH

text

## 🛡️ Security Recommendations

Based on analysis results, the system provides specific recommendations:

### **For MALICIOUS URLs:**
- 🚫 Do not visit or interact with the URL
- 📧 Report to security services (PhishTank, Google Safe Browsing)
- ⚠️ Warn colleagues if received via email
- 🔒 Change passwords if credentials were entered

### **For SUSPICIOUS URLs:**
- ✅ Verify legitimacy through official channels
- 🔍 Check for typosquatting in domain name
- 🛡️ Use additional security tools before visiting

## 🔧 Troubleshooting

### **Common Issues:**

1. **VirusTotal API Errors:**
❌ VirusTotal initialization failed

text
**Solution:** Check your API key is correctly set

2. **Import Errors:**
ModuleNotFoundError: No module named 'xgboost'

text
**Solution:** Run `pip install -r requirements.txt`

3. **Permission Errors:**
PermissionError: [Errno 13] Permission denied: 'maliciouslinks.csv'

text
**Solution:** Close any open CSV files and restart

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -m 'Add new feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Support

- **GitHub Issues:** [Report bugs or request features](https://github.com/cassielxyz/malicious-url-detector/issues)
- **Email:** For security-related inquiries
- **Documentation:** Check the `docs/` folder for additional guides

## 🎓 Educational Use

This tool is perfect for:
- **Cybersecurity Training** - Learn threat detection techniques
- **Academic Research** - Study malicious URL patterns
- **Security Awareness** - Demonstrate web-based threats
- **Professional Development** - Understand ML-based security

---

**⚠️ Disclaimer:** This tool is for educational and legitimate security purposes only. Users are responsible for complying with applicable laws and ethical guidelines.

**🔒 Built for cybersecurity professionals, researchers, and organizations serious about web-based threat detection.**
