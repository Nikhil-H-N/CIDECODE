# APK Threat Analysis Platform

AI-powered Android malware analysis platform for cybersecurity investigators. Performs static analysis, C2 detection, threat scoring, and generates forensic reports.

## Tech Stack

**Backend**
- Python 3.14 + FastAPI
- MongoDB
- androguard (APK parsing)
- yara-python (rule-based detection)
- WeasyPrint (PDF reports)

**Frontend**
- React + TypeScript + Vite
- TailwindCSS
- Recharts (data visualization)

**Analysis Engine**
- Static analysis (permissions, strings, certificates, native libs)
- C2 detection (DGA, beaconing, IOC matching, geolocation)
- 19 YARA rules (banking trojans, ransomware, spyware, cryptominers, etc.)
- ML classification — ONNX model (coming soon) with rule-based fallback
- MITRE ATT&CK mapping
