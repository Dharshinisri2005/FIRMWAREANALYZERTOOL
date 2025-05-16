import sys
import os
import hashlib
import binascii
import struct
import re
import json
import zipfile
import tempfile
import threading
import webbrowser
import subprocess
import difflib
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
import numpy as np
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font
from tkinter.scrolledtext import ScrolledText
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.cm as cm
from PIL import Image, ImageTk
import yara
import lief
import capstone
import pefile

class FirmwareAnalyzer:
    def __init__(self):
        self.firmware_path = None
        self.firmware_data = None
        self.file_size = 0
        self.file_name = ""
        self.md5 = ""
        self.sha1 = ""
        self.sha256 = ""
        self.strings_found = []
        self.potential_vulnerabilities = []
        self.entropy_values = []
        self.file_types = {}
        self.suspicious_patterns = []
        self.firmware_components = []
        self.analysis_start_time = None
        self.analysis_end_time = None
        self.string_categories = {
            'urls': [], 'emails': [], 'ips': [], 'paths': [],
            'credentials': [], 'apis': [], 'certificates': []
        }
        self.yara_rules = None
        self.reference_firmware = None
        self.capstone_engine = None
        self.symbolic_execution_results = []
        self.emulation_results = []
        self.patch_analysis = []
        self.side_channel_findings = []
        self.exploit_mitigations = {
            'NX': False, 'ASLR': False, 'Stack Canary': False,
            'RELRO': 'None', 'PIE': False
        }
        
    def load_firmware(self, path):
        self.firmware_path = path
        self.file_name = os.path.basename(path)
        
        try:
            with open(path, 'rb') as f:
                self.firmware_data = f.read()
                self.file_size = len(self.firmware_data)
            
            self.calculate_hashes()
            self.load_yara_rules()
            return True
        except Exception as e:
            return str(e)
    
    def load_yara_rules(self):
        try:
            rules = """
                rule private_key {
                    strings:
                        $pk1 = /-----BEGIN RSA PRIVATE KEY-----/
                        $pk2 = /-----BEGIN DSA PRIVATE KEY-----/
                        $pk3 = /-----BEGIN EC PRIVATE KEY-----/
                        $pk4 = /-----BEGIN PRIVATE KEY-----/
                    condition:
                        any of them
                }
                
                rule suspicious_strings {
                    strings:
                        $s1 = "backdoor" nocase
                        $s2 = "admin" nocase
                        $s3 = "password" nocase
                        $s4 = "root:" nocase
                    condition:
                        any of them
                }
                
                rule crypto_constants {
                    strings:
                        $aes_sbox = {
                           63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
                           CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
                           B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
                           04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
                        }
                    condition:
                        $aes_sbox
                }
            """
            self.yara_rules = yara.compile(source=rules)
        except Exception as e:
            print(f"YARA rule compilation failed: {e}")
    
    def load_reference_firmware(self, path):
        """Load a reference firmware for differential analysis"""
        try:
            with open(path, 'rb') as f:
                self.reference_firmware = f.read()
            return True
        except Exception as e:
            return str(e)
    
    def calculate_hashes(self):
        self.md5 = hashlib.md5(self.firmware_data).hexdigest()
        self.sha1 = hashlib.sha1(self.firmware_data).hexdigest()
        self.sha256 = hashlib.sha256(self.firmware_data).hexdigest()
    
    def extract_strings(self, min_length=4):
        self.strings_found = []
        
        # ASCII strings extraction
        ascii_pattern = re.compile(b'[ -~]{%d,}' % min_length)
        for match in ascii_pattern.finditer(self.firmware_data):
            self.strings_found.append(match.group(0).decode('ascii', errors='ignore'))
        
        # UTF-16 strings extraction
        utf16_pattern = re.compile(b'(?:[ -~]\x00){%d,}' % min_length)
        for match in utf16_pattern.finditer(self.firmware_data):
            try:
                decoded = match.group(0).decode('utf-16le', errors='ignore')
                self.strings_found.append(decoded)
            except:
                pass
        
        # UTF-8 strings with non-ASCII characters
        try:
            text = self.firmware_data.decode('utf-8', errors='ignore')
            utf8_pattern = re.compile(r'[^\x00-\x7F]{%d,}' % min_length)
            for match in utf8_pattern.finditer(text):
                self.strings_found.append(match.group(0))
        except:
            pass
            
        self.categorize_strings()
        self.apply_yara_rules()
    
    def apply_yara_rules(self):
        if not self.yara_rules:
            return
            
        matches = self.yara_rules.match(data=self.firmware_data)
        for match in matches:
            for string_match in match.strings:
                self.suspicious_patterns.append({
                    'type': 'YARA Rule Match',
                    'rule': match.rule,
                    'offset': string_match.instances[0].offset,
                    'matched': string_match.identifier,
                    'severity': 'High' if match.rule == 'private_key' else 'Medium'
                })
    
    def categorize_strings(self):
        self.string_categories = {k: [] for k in self.string_categories.keys()}
        
        patterns = {
            'urls': r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[a-zA-Z0-9./?=_%&-]*',
            'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ips': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'paths': r'[/\\][a-zA-Z0-9_.-]+[/\\][a-zA-Z0-9_.-]+',
            'credentials': r'pass(word)?|user(name)?|login|key|secret|token|auth|cred',
            'apis': r'api[_-]?key|client[_-]?id|app[_-]?key|access[_-]?token',
            'certificates': r'-----BEGIN CERTIFICATE-----|ssl|tls|x509|subject|issuer'
        }
        
        for s in self.strings_found:
            for category, pattern in patterns.items():
                if re.search(pattern, s, re.IGNORECASE):
                    self.string_categories[category].append(s)
    
    def calculate_entropy(self, block_size=1024):
        self.entropy_values = []
        self.block_positions = []
        
        for i in range(0, self.file_size, block_size):
            block = self.firmware_data[i:i+block_size]
            if not block:
                break
                
            entropy = self._calculate_block_entropy(block)
            self.block_positions.append(i)    
            self.entropy_values.append(entropy)
            
            if entropy > 7.8:
                self.suspicious_patterns.append({
                    'type': 'High Entropy',
                    'offset': i,
                    'size': len(block),
                    'description': f'Possible encrypted/compressed data at offset {i} (entropy: {entropy:.2f})',
                    'severity': 'Info'
                })
    
    def _calculate_block_entropy(self, data):
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
                
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
            
        return entropy
    
    def identify_file_types(self):
        self.file_types = {}
        
        signatures = {
            b'\x7FELF': 'ELF binary',
            b'MZ': 'Windows executable',
            b'PK\x03\x04': 'ZIP archive',
            b'\x1F\x8B\x08': 'GZIP archive',
            b'SQLite': 'SQLite database',
            b'\xFF\xD8\xFF': 'JPEG image',
            b'\x89PNG': 'PNG image',
            b'<html': 'HTML file',
            b'<?xml': 'XML file',
            b'#!/bin/sh': 'Shell script',
            b'#!/bin/bash': 'Bash script',
            b'#include': 'C source code',
            b'import ': 'Python code',
            b'function ': 'JavaScript code',
            b'\x42\x5A\x68': 'BZIP2 archive',
            b'\x75\x73\x74\x61\x72': 'TAR archive',
            b'\xFD\x37\x7A\x58\x5A\x00': 'XZ archive',
            b'\x04\x22\x4D\x18': 'LZ4 compressed',
            b'\x28\xB5\x2F\xFD': 'ZSTD compressed',
            b'\xCA\xFE\xBA\xBE': 'Java class file',
            b'\x25\x50\x44\x46': 'PDF document',
            b'\xD0\xCF\x11\xE0': 'Microsoft Office document',
            b'\x52\x61\x72\x21': 'RAR archive'
        }
        
        for i in range(0, min(self.file_size, 10240), 512):
            block = self.firmware_data[i:i+512]
            for sig, filetype in signatures.items():
                if sig in block:
                    if filetype not in self.file_types:
                        self.file_types[filetype] = 0
                        self.firmware_components.append({
                            'type': filetype,
                            'offset': i,
                            'signature': sig.decode('ascii', errors='replace')
                        })
                    self.file_types[filetype] += 1
    
    def scan_vulnerabilities(self):
        self.potential_vulnerabilities = []
        
        vulns = [
            ('strcpy', 'Buffer overflow risk - unsafe string copy', 'High', 'Use strncpy() or strlcpy() with proper length checking'),
            ('strcat', 'Buffer overflow risk - unsafe string concat', 'High', 'Use strncat() or strlcat() with proper length checking'),
            ('gets', 'Buffer overflow risk - unsafe input', 'Critical', 'Use fgets() with proper buffer size'),
            ('sprintf', 'Buffer overflow risk - unsafe formatting', 'High', 'Use snprintf() with length limit'),
            ('system', 'Command injection risk', 'Critical', 'Avoid system() calls or sanitize inputs'),
            ('exec', 'Command execution risk', 'Critical', 'Avoid exec functions or sanitize inputs'),
            ('memcpy', 'Potential buffer overflow', 'Medium', 'Ensure proper boundary checks'),
            ('scanf', 'Format string vulnerability', 'High', 'Use scanf with field width limits'),
            ('malloc', 'Memory allocation without checks', 'Medium', 'Check malloc return value'),
            ('free', 'Potential double-free vulnerability', 'Medium', 'Ensure proper memory management'),
            ('DEBUG', 'Debug code in firmware', 'Medium', 'Remove debug code in production'),
            ('password', 'Hardcoded password', 'Critical', 'Remove hardcoded credentials'),
            ('backdoor', 'Potential backdoor', 'Critical', 'Investigate and remove'),
            ('http://', 'Unencrypted HTTP usage', 'Medium', 'Switch to HTTPS'),
            ('md5', 'Weak hashing algorithm', 'Medium', 'Use SHA-256 or better'),
            ('eval(', 'Potential code injection', 'Critical', 'Avoid dynamic code evaluation'),
            ('PRIVATE KEY', 'Private key in firmware', 'Critical', 'Remove sensitive cryptographic material'),
            ('setuid', 'Privilege escalation', 'High', 'Review privileged operations')
        ]
        
        for string in self.strings_found:
            for pattern, desc, severity, mitigation in vulns:
                if pattern.lower() in string.lower():
                    self.potential_vulnerabilities.append({
                        'pattern': pattern,
                        'description': desc,
                        'severity': severity,
                        'context': string,
                        'mitigation': mitigation
                    })
    
    def detect_suspicious_patterns(self):
        patterns = [
            (r'(/etc/passwd|/etc/shadow)', 'Access to system password files', 'Critical'),
            (r'(192\.168\.0\.|10\.0\.0\.|172\.16\.)', 'Hardcoded private IP address', 'Medium'),
            (r'(ssh-rsa|ssh-dss)', 'SSH key in firmware', 'High'),
            (r'(\\x[0-9a-f]{2}){8,}', 'Potential shellcode/binary data', 'High'),
            (r'(BEGIN CERTIFICATE|BEGIN PRIVATE KEY)', 'Embedded certificate material', 'Critical'),
            (r'(\[DEBUG\]|\[TEST\]|\[DEV\])', 'Development markers in production code', 'Medium')
        ]
        
        for string in self.strings_found:
            for pattern, desc, severity in patterns:
                if re.search(pattern, string, re.IGNORECASE):
                    self.suspicious_patterns.append({
                        'pattern': pattern,
                        'description': desc, 
                        'context': string,
                        'severity': severity
                    })
    
    def extract_firmware_components(self):
        extracted_files = []
        
        if zipfile.is_zipfile(self.firmware_path):
            temp_dir = tempfile.mkdtemp()
            try:
                with zipfile.ZipFile(self.firmware_path, 'r') as zip_ref:
                    zip_ref.extractall(temp_dir)
                    extracted_files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(temp_dir) for f in filenames]
            except:
                pass
        
        return extracted_files
    
    def perform_differential_analysis(self, reference_path):
        """Compare current firmware with a reference version"""
        if not self.reference_firmware:
            if not self.load_reference_firmware(reference_path):
                return False
                
        current_hashes = self._create_firmware_hashes(self.firmware_data)
        ref_hashes = self._create_firmware_hashes(self.reference_firmware)
        
        diff = difflib.unified_diff(
            ref_hashes, current_hashes,
            fromfile='reference', tofile='current',
            lineterm=''
        )
        
        differences = list(diff)
        if differences:
            self.patch_analysis = differences
            return True
        return False
    
    def _create_firmware_hashes(self, data, block_size=1024):
        """Create a list of block hashes for comparison"""
        hashes = []
        for i in range(0, len(data), block_size):
            block = data[i:i+block_size]
            hashes.append(hashlib.sha256(block).hexdigest())
        return hashes
    
    def analyze_binary_security(self):
        """Check for common binary security features"""
        try:
            if self.firmware_data[:4] == b'\x7FELF':
                binary = lief.parse(self.firmware_data)
                if binary:
                    self.exploit_mitigations['NX'] = binary.has_nx
                    self.exploit_mitigations['PIE'] = binary.is_pie
                    
                    # Check RELRO level
                    if binary.has_full_relro:
                        self.exploit_mitigations['RELRO'] = 'Full'
                    elif binary.has_partial_relro:
                        self.exploit_mitigations['RELRO'] = 'Partial'
                    
                    # Check for stack canary
                    self.exploit_mitigations['Stack Canary'] = any(
                        s.name == '__stack_chk_fail' for s in binary.imported_functions
                    )
        except Exception as e:
            print(f"Binary analysis failed: {e}")
    
    def scan_crypto_material(self):
        """Enhanced cryptographic material scanner"""
        crypto_patterns = [
            (b'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key'),
            (b'-----BEGIN DSA PRIVATE KEY-----', 'DSA Private Key'),
            (b'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key'),
            (b'-----BEGIN PRIVATE KEY-----', 'PKCS8 Private Key'),
            (b'-----BEGIN CERTIFICATE-----', 'X.509 Certificate'),
            (b'-----BEGIN PUBLIC KEY-----', 'Public Key'),
            (b'-----BEGIN PGP', 'PGP Key'),
            (b'ssh-rsa', 'SSH RSA Key'),
            (b'ssh-dss', 'SSH DSA Key'),
            (b'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
            (b'sk_live_[0-9a-z]{32}', 'Stripe Secret Key')
        ]
        
        for pattern, desc in crypto_patterns:
            matches = re.finditer(re.escape(pattern), self.firmware_data)
            for match in matches:
                self.suspicious_patterns.append({
                    'type': 'Crypto Material',
                    'description': desc,
                    'offset': match.start(),
                    'severity': 'Critical',
                    'context': match.group(0).decode('ascii', errors='replace')[:100]
                })
    
    def detect_side_channels(self):
        """Basic side channel vulnerability detection"""
        # Look for timing-sensitive operations
        timing_keywords = [
            'strcmp', 'memcmp', '==', '!=', 
            'password', 'secret', 'key', 'token'
        ]
        
        for string in self.strings_found:
            for keyword in timing_keywords:
                if keyword in string.lower():
                    self.side_channel_findings.append({
                        'type': 'Potential Timing Side Channel',
                        'context': string,
                        'severity': 'Medium',
                        'description': f'Potential timing side channel in {string[:50]}...'
                    })
    
    def run_full_analysis(self):
        self.analysis_start_time = datetime.now()
        
        self.extract_strings()
        self.calculate_entropy()
        self.identify_file_types()
        self.scan_vulnerabilities()
        self.detect_suspicious_patterns()
        self.analyze_binary_security()
        self.scan_crypto_material()
        self.detect_side_channels()
        
        self.analysis_end_time = datetime.now()
        
        return self.generate_reports()
    
    def generate_reports(self):
        reports = {}
        
        reports['file_types'] = {
            'title': 'File Type Distribution',
            'data': self.file_types,
            'type': 'pie'
        }
        
        string_cat_data = {k: len(v) for k, v in self.string_categories.items()}
        reports['string_categories'] = {
            'title': 'String Category Distribution',
            'data': string_cat_data,
            'type': 'bar'
        }
        
        vuln_severity = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.potential_vulnerabilities:
            vuln_severity[vuln['severity']] += 1
        
        reports['vulnerability_severity'] = {
            'title': 'Vulnerability Severity Distribution',
            'data': vuln_severity,
            'type': 'pie'
        }
        
        reports['entropy'] = {
            'title': 'Firmware Entropy Analysis',
            'data': self.entropy_values,
            'positions': self.block_positions,
            'type': 'line'
        }
        
        reports['exploit_mitigations'] = {
            'title': 'Exploit Mitigation Techniques',
            'data': self.exploit_mitigations,
            'type': 'table'
        }
        
        reports['security_score'] = {
            'title': 'Security Risk Assessment',
            'data': self.calculate_security_score(),
            'type': 'gauge'
        }
        
        return reports
    
    def calculate_security_score(self):
        # Calculate a security score based on findings
        # Higher score is worse (more vulnerabilities)
        score_weights = {
            'Critical': 10,
            'High': 5,
            'Medium': 2,
            'Low': 1
        }
        
        total_score = 0
        max_score = 100
        
        # Add vulnerability scores
        for vuln in self.potential_vulnerabilities:
            total_score += score_weights.get(vuln['severity'], 0)
        
        # Add suspicious pattern scores
        for pattern in self.suspicious_patterns:
            total_score += score_weights.get(pattern['severity'], 0)
        
        # Cap at max score
        total_score = min(total_score, max_score)
        
        risk_categories = {
            (0, 20): 'Low Risk',
            (20, 40): 'Moderate Risk',
            (40, 70): 'High Risk',
            (70, 101): 'Critical Risk'
        }
        
        for (min_val, max_val), category in risk_categories.items():
            if min_val <= total_score < max_val:
                risk_level = category
                break
        else:
            risk_level = 'Unknown Risk'
        
        return {
            'score': total_score,
            'max_score': max_score,
            'risk_level': risk_level
        }
    
    def export_report(self, output_path):
        if not self.analysis_end_time:
            return False
            
        analysis_duration = (self.analysis_end_time - self.analysis_start_time).total_seconds()
            
        report = {
            'firmware_info': {
                'filename': self.file_name,
                'size': self.file_size,
                'md5': self.md5,
                'sha1': self.sha1,
                'sha256': self.sha256,
                'analysis_date': self.analysis_end_time.strftime('%Y-%m-%d %H:%M:%S'),
                'analysis_duration': f"{analysis_duration:.2f} seconds"
            },
            'vulnerabilities': self.potential_vulnerabilities,
            'suspicious_patterns': self.suspicious_patterns,
            'string_categories': {k: len(v) for k, v in self.string_categories.items()},
            'file_types': self.file_types,
            'firmware_components': self.firmware_components,
            'security_score': self.calculate_security_score(),
            'exploit_mitigations': self.exploit_mitigations,
            'side_channel_findings': self.side_channel_findings
        }
        
        try:
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
            return True
        except:
            return False

class FirmwareAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Firmware Extraction & Analysis Tool")
        self.root.geometry("1200x800")
        
        # Set theme colors
        self.colors = {
            'bg': '#f0f0f0',
            'header_bg': '#2c3e50',
            'header_fg': 'white',
            'accent': '#3498db',
            'accent_hover': '#2980b9',
            'text': '#333333',
            'success': '#27ae60', 
            'warning': '#f39c12',
            'danger': '#e74c3c',
            'info': '#3498db'
        }
        
        # Configure ttk style
        self.style = ttk.Style()
        self.style.configure('TFrame', background=self.colors['bg'])
        self.style.configure('TLabel', background=self.colors['bg'], foreground=self.colors['text'])
        self.style.configure('TButton', background=self.colors['accent'], foreground='white')
        self.style.configure('Accent.TButton', background=self.colors['accent'], foreground='white')
        self.style.map('Accent.TButton', 
                  background=[('active', self.colors['accent_hover'])])
        self.style.configure('Header.TLabel', background=self.colors['header_bg'], foreground=self.colors['header_fg'], font=('Arial', 12, 'bold'))
        self.style.configure('Critical.TLabel', foreground=self.colors['danger'], font=('Arial', 10, 'bold'))
        self.style.configure('High.TLabel', foreground='#e67e22', font=('Arial', 10, 'bold'))
        self.style.configure('Medium.TLabel', foreground=self.colors['warning'], font=('Arial', 10))
        self.style.configure('Low.TLabel', foreground=self.colors['success'], font=('Arial', 10))
        
        # Load analyzer
        self.analyzer = FirmwareAnalyzer()
        
        # Progress variables
        self.progress_var = tk.DoubleVar()
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        # Analysis results
        self.reports = None
        
        # Create UI components
        self.create_menu()
        self.create_gui()
        
        # Splash screen on start
        self.show_splash_screen()
    
    def show_splash_screen(self):
        splash = tk.Toplevel(self.root)
        splash.title("Firmware Analyzer")
        splash.geometry("500x300")
        splash.configure(bg="#2c3e50")
        splash.transient(self.root)
        splash.grab_set()
        
        # Center splash on screen
        splash.update_idletasks()
        width = splash.winfo_width()
        height = splash.winfo_height()
        x = (splash.winfo_screenwidth() // 2) - (width // 2)
        y = (splash.winfo_screenheight() // 2) - (height // 2)
        splash.geometry(f'+{x}+{y}')
        
        # Application title
        title_label = tk.Label(splash, text="Advanced Firmware Analyzer", 
                              font=("Arial", 24, "bold"), fg="white", bg="#2c3e50")
        title_label.pack(pady=20)
        
        # Version info
        version_label = tk.Label(splash, text="Version 2.0", 
                               font=("Arial", 12), fg="#3498db", bg="#2c3e50")
        version_label.pack()
        
        # Feature list
        features_frame = tk.Frame(splash, bg="#2c3e50")
        features_frame.pack(pady=20, fill=tk.X, padx=30)
        
        features = [
            "✓ Firmware extraction and analysis",
            "✓ Vulnerability detection and mitigation",
            "✓ Entropy analysis and visualization",
            "✓ Comprehensive reporting capabilities",
            "✓ Advanced forensic insights"
        ]
        
        for feature in features:
            feature_label = tk.Label(features_frame, text=feature, 
                                   font=("Arial", 11), fg="#ecf0f1", bg="#2c3e50", anchor="w")
            feature_label.pack(fill=tk.X, pady=3)
        
        # Close button
        close_button = tk.Button(splash, text="Start Analyzing", 
                               font=("Arial", 12), fg="white", bg="#3498db",
                               command=splash.destroy)
        close_button.pack(pady=10)
        
        # Auto close after 3 seconds
        self.root.after(3000, splash.destroy)
    
    def create_menu(self):
        menu_bar = tk.Menu(self.root)
        self.root.config(menu=menu_bar)
        
        # File menu
        file_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open Firmware...", command=self.select_file)
        file_menu.add_command(label="Load Reference Firmware...", command=self.load_reference)
        file_menu.add_command(label="Export Report...", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Analysis menu
        analysis_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Run Full Analysis", command=self.start_analysis)
        analysis_menu.add_command(label="Differential Analysis", command=self.run_differential_analysis)
        analysis_menu.add_command(label="Scan for Vulnerabilities", command=lambda: self.start_analysis(scan_only=True))
        analysis_menu.add_command(label="Extract Strings", command=lambda: self.start_analysis(strings_only=True))
        analysis_menu.add_command(label="Analyze Binary Security", command=self.analyze_binary_security)
        
        # Tools menu
        tools_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Entropy Analyzer", command=lambda: self.notebook.select(2))
        tools_menu.add_command(label="String Extractor", command=lambda: self.notebook.select(3))
        tools_menu.add_command(label="Vulnerabilities Scanner", command=lambda: self.notebook.select(1))
        tools_menu.add_command(label="Binary Security", command=lambda: self.notebook.select(4))
        
        # Help menu
        help_menu = tk.Menu(menu_bar, tearoff=0)
        menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=lambda: webbrowser.open("https://example.com/docs"))
    
    def create_gui(self):
        main_container = ttk.Frame(self.root, padding=10)
        main_container.pack(fill=tk.BOTH, expand=True)
    
        # Header section
        header_frame = ttk.Frame(main_container)
        header_frame.pack(fill=tk.X, pady=(0, 10))
    
        logo_canvas = tk.Canvas(header_frame, width=40, height=40, bd=0, highlightthickness=0)
        logo_canvas.pack(side=tk.LEFT, padx=(0, 10))
        logo_canvas.create_rectangle(5, 5, 35, 35, fill="#3498db", outline="")
        logo_canvas.create_text(20, 20, text="FA", fill="white", font=("Arial", 14, "bold"))
    
        title_label = ttk.Label(header_frame, text="Advanced Firmware Analyzer", style="Header.TLabel", font=("Arial", 16, "bold"))
        title_label.pack(side=tk.LEFT)
    
        # Control frame
        control_frame = ttk.Frame(main_container)
        control_frame.pack(fill=tk.X, pady=(0, 10))

        # File selection
        self.file_entry = ttk.Entry(control_frame, width=50)
        self.file_entry.pack(side=tk.LEFT, padx=(0, 10))

        browse_button = ttk.Button(control_frame, text="Browse...", command=self.select_file)
        browse_button.pack(side=tk.LEFT)

        # Analysis buttons
        analyze_button = ttk.Button(control_frame, text="Run Full Analysis", command=self.start_analysis)
        analyze_button.pack(side=tk.LEFT, padx=(10, 5))

        diff_button = ttk.Button(control_frame, text="Differential Analysis", command=self.run_differential_analysis)
        diff_button.pack(side=tk.LEFT, padx=5)

        scan_button = ttk.Button(control_frame, text="Scan Vulnerabilities", command=lambda: self.start_analysis(scan_only=True))
        scan_button.pack(side=tk.LEFT, padx=5)

        # Progress bar and status label
        self.progress_bar = ttk.Progressbar(control_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.LEFT, padx=(10, 5), fill=tk.X, expand=True)

        self.status_label = ttk.Label(control_frame, textvariable=self.status_var)
        self.status_label.pack(side=tk.LEFT, padx=(5, 0))

        # Notebook for different analysis views
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Vulnerability tab
        self.vuln_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vuln_frame, text="Vulnerabilities")

        self.vuln_tree = ttk.Treeview(self.vuln_frame, columns=("Severity", "Description", "Context", "Mitigation"), show="headings")
        self.vuln_tree.heading("Severity", text="Severity")
        self.vuln_tree.heading("Description", text="Description")
        self.vuln_tree.heading("Context", text="Context")
        self.vuln_tree.heading("Mitigation", text="Mitigation")
        self.vuln_tree.pack(fill=tk.BOTH, expand=True)

        # Entropy analysis tab
        self.entropy_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.entropy_frame, text="Entropy Analysis")

        self.entropy_fig = Figure(figsize=(8, 4), dpi=100)
        self.entropy_ax = self.entropy_fig.add_subplot(111)
        self.entropy_canvas = FigureCanvasTkAgg(self.entropy_fig, self.entropy_frame)
        self.entropy_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        # Strings tab
        self.strings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.strings_frame, text="Strings")
  
        self.strings_text = ScrolledText(self.strings_frame, wrap=tk.WORD)
        self.strings_text.pack(fill=tk.BOTH, expand=True)

        # Binary Security tab
        self.binary_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.binary_frame, text="Binary Security")
        
        self.binary_tree = ttk.Treeview(self.binary_frame, columns=("Feature", "Status"), show="headings")
        self.binary_tree.heading("Feature", text="Security Feature")
        self.binary_tree.heading("Status", text="Status")
        self.binary_tree.pack(fill=tk.BOTH, expand=True)

        # Reports tab
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text="Reports")

        self.reports_text = ScrolledText(self.reports_frame, wrap=tk.WORD)
        self.reports_text.pack(fill=tk.BOTH, expand=True)
    
    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Firmware files", "*.bin *.img *.zip"), ("All files", "*.*")])
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            if self.analyzer.load_firmware(file_path):
                self.status_var.set("Firmware loaded successfully")
            else:
                self.status_var.set("Failed to load firmware")
    
    def load_reference(self):
        file_path = filedialog.askopenfilename(filetypes=[("Firmware files", "*.bin *.img *.zip"), ("All files", "*.*")])
        if file_path:
            if self.analyzer.load_reference_firmware(file_path):
                messagebox.showinfo("Success", "Reference firmware loaded successfully")
            else:
                messagebox.showerror("Error", "Failed to load reference firmware")
    
    def run_differential_analysis(self):
        if not self.analyzer.firmware_data:
            messagebox.showerror("Error", "No firmware file loaded")
            return
            
        reference_path = filedialog.askopenfilename(filetypes=[("Firmware files", "*.bin *.img *.zip"), ("All files", "*.*")])
        if not reference_path:
            return
            
        self.progress_var.set(0)
        self.status_var.set("Running differential analysis...")
        
        def diff_thread():
            if self.analyzer.perform_differential_analysis(reference_path):
                self.status_var.set("Differential analysis completed")
                self.update_reports_view()
            else:
                self.status_var.set("No differences found")
            self.progress_var.set(100)
            
        threading.Thread(target=diff_thread).start()
    
    def analyze_binary_security(self):
        if not self.analyzer.firmware_data:
            messagebox.showerror("Error", "No firmware file loaded")
            return
            
        self.progress_var.set(0)
        self.status_var.set("Analyzing binary security features...")
        
        def analysis_thread():
            self.analyzer.analyze_binary_security()
            self.status_var.set("Binary security analysis completed")
            self.update_binary_security_view()
            self.progress_var.set(100)
            
        threading.Thread(target=analysis_thread).start()
    
    def update_binary_security_view(self):
        self.binary_tree.delete(*self.binary_tree.get_children())
        for feature, status in self.analyzer.exploit_mitigations.items():
            self.binary_tree.insert("", tk.END, values=(feature, status))
    
    def start_analysis(self, scan_only=False, strings_only=False):
        if not self.analyzer.firmware_data:
            messagebox.showerror("Error", "No firmware file loaded")
            return

        self.progress_var.set(0)
        self.status_var.set("Starting analysis...")

        def analysis_thread():
            if strings_only:
                self.analyzer.extract_strings()
                self.status_var.set("Strings extracted")
                self.update_strings_view()
            elif scan_only:
                self.analyzer.scan_vulnerabilities()
                self.status_var.set("Vulnerability scan completed")
                self.update_vulnerabilities_view()
            else:
                self.analyzer.run_full_analysis()
                self.status_var.set("Full analysis completed")
                self.update_all_views()

            self.progress_var.set(100)

        threading.Thread(target=analysis_thread).start()

    def update_vulnerabilities_view(self):
        self.vuln_tree.delete(*self.vuln_tree.get_children())
        for vuln in self.analyzer.potential_vulnerabilities:
            self.vuln_tree.insert("", tk.END, values=(vuln['severity'], vuln['description'], vuln['context'], vuln['mitigation']))

    def update_strings_view(self):
        self.strings_text.delete(1.0, tk.END)
        for string in self.analyzer.strings_found:
            self.strings_text.insert(tk.END, string + "\n")

    def update_all_views(self):
        self.update_vulnerabilities_view()
        self.update_strings_view()
        self.update_entropy_plot()
        self.update_reports_view()
        self.update_binary_security_view()

    def update_entropy_plot(self):
        self.entropy_ax.clear()
        self.entropy_ax.plot(self.analyzer.block_positions, self.analyzer.entropy_values, label="Entropy")
        self.entropy_ax.set_xlabel("Offset")
        self.entropy_ax.set_ylabel("Entropy")
        self.entropy_ax.set_title("Firmware Entropy Analysis")
        self.entropy_ax.legend()
        self.entropy_canvas.draw()

    def update_reports_view(self):
        self.reports_text.delete(1.0, tk.END)
        reports = self.analyzer.generate_reports()
        for report_name, report_data in reports.items():
            self.reports_text.insert(tk.END, f"{report_data['title']}\n")
            self.reports_text.insert(tk.END, f"{json.dumps(report_data['data'], indent=2)}\n\n")

    def export_report(self):
        if not self.analyzer.analysis_end_time:
            messagebox.showerror("Error", "No analysis results to export")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            if self.analyzer.export_report(file_path):
                messagebox.showinfo("Success", "Report exported successfully")
            else:
                messagebox.showerror("Error", "Failed to export report")

    def show_about(self):
        about_window = tk.Toplevel(self.root)
        about_window.title("About Firmware Analyzer")
        about_window.geometry("400x300")
        about_window.configure(bg="#2c3e50")
        about_window.transient(self.root)
        about_window.grab_set()
        
        # Center window
        about_window.update_idletasks()
        width = about_window.winfo_width()
        height = about_window.winfo_height()
        x = (about_window.winfo_screenwidth() // 2) - (width // 2)
        y = (about_window.winfo_screenheight() // 2) - (height // 2)
        about_window.geometry(f'+{x}+{y}')
        
        # About content
        title_label = tk.Label(about_window, text="Advanced Firmware Analyzer", 
                              font=("Arial", 16, "bold"), fg="white", bg="#2c3e50")
        title_label.pack(pady=20)
        
        info_text = """
        Version 2.0
        
        A comprehensive tool for firmware extraction,
        analysis, and vulnerability detection.
        
        © 2025 Cybersecurity Tools Inc.
        """
        
        info_label = tk.Label(about_window, text=info_text, 
                            font=("Arial", 10), fg="#ecf0f1", bg="#2c3e50")
        info_label.pack(pady=10)
        
        close_button = tk.Button(about_window, text="Close", 
                               bg="#3498db", fg="white",
                               command=about_window.destroy)
        close_button.pack(pady=20)

if __name__ == "__main__":
    root = tk.Tk()
    app = FirmwareAnalyzerGUI(root)
    root.mainloop()