# Advanced-Port-Scanner-
# 🔍 PortScanner - Advanced Network Vulnerability Scanner

A powerful Python-based port scanning and vulnerability assessment tool that detects open ports, OS info, WHOIS, GeoIP, and checks for common web vulnerabilities like SQL Injection and XSS.

IMPORTANT NOTE :- This tool is designed for educational and authorized penetration testing purposes only. Do not scan any IP or network you do not own or have explicit permission to test.
This tool is for educational and ethical hacking purposes only. Do not use it on systems without proper authorization. Unauthorized scanning may be illegal.

Make sure you have Python 3.x installed on your system.
Install required dependencies using:
pip install -r requirements.txt


---

## 📌 Features

- ✅ Scans for open TCP ports
- 🧠 OS Detection
- 🌍 GeoIP Information Lookup
- 🌐 WHOIS Data Retrieval
- 🕳️ SQL Injection & XSS Vulnerability Checks
- 🔐 SSH & FTP Brute Forcing (Basic)
- 💣 Metasploit Exploit Trigger (if installed)
- 🌑 Dark Web Data Scan *(Placeholder)*
- 📄 PDF Report Generation (with `pdfkit` + `wkhtmltopdf`)

---
Required Tools
wkhtmltopdf: Download & Install

Optional: Metasploit (for exploit module)


🚀 How to Run
python PortScanner.py

You will be prompted to enter:
Target IP / Domain
Start Port
End Port

For Example:-
Enter Target IP/Domain: 192.168.1.1
Enter Start Port: 1
Enter End Port: 300

📸 Screenshots
🎯 Open Port Scan:
🌍 GeoIP and WHOIS Data:

📂 Project Structure
PortScanner/
│
├── PortScanner.py
├── requirements.txt
├── README.md
└── screenshots/
    ├── portscan.png
    └── geoip.png

    
📥 Output
Open ports and vulnerabilities are logged
Optional: Generate a PDF report of results
All logs are saved in the terminal or can be redirected to file



## 🛠️ Requirements

- Python 3.8+
- Install dependencies:
pip install -r requirements.txt



If you found this project helpful:

⭐ Star this repo
🍴 Fork it
🐛 Submit Issues or PRs

