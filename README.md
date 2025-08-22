# Fake QR Code Detector

A Python-based web application to detect and prevent malicious QR codes (“Quishing”).  
This tool scans QR codes, extracts embedded URLs, and flags suspicious or phishing links before users interact with them.

---

## 🚀 Features

- Scan QR codes from images and decode embedded URLs  
- Detect unsafe or malicious links using **Google Safe Browsing API** and **VirusTotal API**  
- Dynamic results display with clear safe/unsafe indicators  
- Temporary storage of scanned QR codes (auto-deleted after 1 minute)  
- Built with **Python, Flask, Pyzbar, Pillow, and Requests**  

---

## 🛠️ Technology Stack

- **Backend:** Python (Flask)  
- **Frontend:** HTML5, Bootstrap 5  
- **QR Scanning:** Pyzbar, Pillow  
- **API Integration:** Google Safe Browsing API, VirusTotal API  

---

