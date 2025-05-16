🔍 Advanced Firmware Analyzer

A comprehensive GUI-based tool for performing static firmware analysis, vulnerability detection, and binary inspection, with advanced visualizations and reporting features.

🚀 Features
🔎 Extract strings (ASCII, UTF-16, UTF-8) and categorize them (URLs, emails, credentials, etc.)

🛡️ Detect potential vulnerabilities and unsafe functions

🧪 Entropy analysis to identify encrypted or compressed regions

🔬 Binary security checks (NX, PIE, RELRO, Stack Canary)

⚠️ Suspicious patterns and cryptographic material detection (YARA rules included)

🗂️ File type identification and firmware component extraction

📊 Graphical reports (bar, pie, line charts)

🧮 Security score computation with risk levels

📁 Differential analysis against reference firmware

📤 Exportable JSON reports

🛠️ Installation
🐍 Requirements
Make sure Python 3.8+ is installed. Then install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
requirements.txt
nginx
Copy
Edit
tk
lief
yara-python
capstone
pefile
matplotlib
numpy
Pillow
Optional: You may need libyara installed on your system for yara-python.

📦 How to Run
bash
Copy
Edit
python n.py
A graphical user interface (GUI) will appear.

🧑‍💻 Usage
Open a firmware file (.bin, .img, or .zip)

Click Run Full Analysis to extract strings, identify entropy regions, scan vulnerabilities, and more.

View results across different tabs:

Vulnerabilities

Entropy Analysis

Strings

Binary Security

Reports

Export a detailed JSON report using File > Export Report.

📁 Output
The generated JSON report includes:

File metadata & hash info

Detected vulnerabilities

Suspicious patterns

File types and components

Exploit mitigation checks

Security score

🧪 Advanced Capabilities
YARA Integration for private key, backdoor, and crypto constant detection

Differential Analysis to compare two firmware versions

Security Score Gauge from Low to Critical Risk

🖼️ GUI Overview
Built with Tkinter and matplotlib

Real-time progress and status updates

Splash screen and tooltips for ease of use

📄 License
© 2025 Cybersecurity Tools Inc. — For educational and research purposes only.
