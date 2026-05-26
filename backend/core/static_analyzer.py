"""
APK Static Analysis Engine
Performs deep static analysis on Android APK files using androguard and auxiliary tools.
"""
import hashlib
import logging
import os
import re
import subprocess
import zipfile
from collections import defaultdict
from typing import Dict, List, Optional, Tuple
from utils.entropy import shannon_entropy as _shannon_entropy, is_high_entropy as _is_high_entropy, entropy_label

logger = logging.getLogger(__name__)

try:
    from androguard.core.bytecodes.apk import APK
    from androguard.core.bytecodes.dvm import DalvikVMFormat
    from androguard.core.analysis.analysis import Analysis
    ANDROGUARD_AVAILABLE = True
except ImportError:
    ANDROGUARD_AVAILABLE = False
    APK = DalvikVMFormat = Analysis = None
    logger.warning("androguard not installed — static analysis will use fallback ZIP parsing")


class PermissionAnalyzer:
    """
    Categorizes Android permissions and computes risk scores.
    Based on Android's permission classification system.
    """

    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_SMS": 9,
        "android.permission.SEND_SMS": 9,
        "android.permission.RECEIVE_SMS": 8,
        "android.permission.RECEIVE_MMS": 5,
        "android.permission.READ_CONTACTS": 7,
        "android.permission.WRITE_CONTACTS": 7,
        "android.permission.READ_CALL_LOG": 8,
        "android.permission.WRITE_CALL_LOG": 8,
        "android.permission.PROCESS_OUTGOING_CALLS": 8,
        "android.permission.RECORD_AUDIO": 10,
        "android.permission.CAMERA": 10,
        "android.permission.ACCESS_FINE_LOCATION": 10,
        "android.permission.ACCESS_COARSE_LOCATION": 8,
        "android.permission.ACCESS_BACKGROUND_LOCATION": 9,
        "android.permission.READ_EXTERNAL_STORAGE": 5,
        "android.permission.WRITE_EXTERNAL_STORAGE": 5,
        "android.permission.READ_PHONE_STATE": 8,
        "android.permission.CALL_PHONE": 8,
        "android.permission.GET_ACCOUNTS": 6,
        "android.permission.USE_CREDENTIALS": 6,
        "android.permission.MANAGE_ACCOUNTS": 7,
        "android.permission.AUTHENTICATE_ACCOUNTS": 6,
        "android.permission.SYSTEM_ALERT_WINDOW": 7,
        "android.permission.WRITE_SETTINGS": 6,
        "android.permission.REQUEST_INSTALL_PACKAGES": 7,
        "android.permission.BIND_ACCESSIBILITY_SERVICE": 10,
        "android.permission.INSTALL_PACKAGES": 10,
        "android.permission.DELETE_PACKAGES": 9,
        "android.permission.KILL_BACKGROUND_PROCESSES": 5,
        "android.permission.RESTART_PACKAGES": 4,
    }

    DANGEROUS_NAMES = set(DANGEROUS_PERMISSIONS.keys())

    NORMAL_PERMISSIONS = {
        "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_NOTIFICATION_POLICY",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.BLUETOOTH",
        "android.permission.BROADCAST_STICKY",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.CHANGE_WIFI_MULTICAST_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.EXPAND_STATUS_BAR",
        "android.permission.FLASHLIGHT",
        "android.permission.GET_PACKAGE_SIZE",
        "android.permission.INTERNET",
        "android.permission.NFC",
        "android.permission.NFC_TRANSACTION_EVENT",
        "android.permission.QUERY_ALL_PACKAGES",
        "android.permission.SET_WALLPAPER",
        "android.permission.SET_WALLPAPER_HINTS",
        "android.permission.TRANSMIT_IR",
        "android.permission.USE_FINGERPRINT",
        "android.permission.USE_BIOMETRIC",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
    }

    def categorize_permissions(self, all_permissions: List[str]) -> Dict[str, List[str]]:
        """Categorize permissions by type."""
        dangerous = []
        normal = []
        signature = []
        custom = []
        for perm in all_permissions:
            if perm in self.DANGEROUS_NAMES:
                dangerous.append(perm)
            elif perm in self.NORMAL_PERMISSIONS or perm.startswith("android.permission."):
                normal.append(perm)
            elif "signature" in perm.lower() or perm.startswith("android."):
                signature.append(perm)
            else:
                custom.append(perm)
        return {
            "dangerous": sorted(dangerous),
            "normal": sorted(normal),
            "signature": sorted(signature),
            "custom": sorted(custom),
        }

    def calculate_risk_score(self, categorized: Dict[str, List[str]]) -> Dict:
        """Calculate permission risk score based on dangerous permissions."""
        max_possible = sum(self.DANGEROUS_PERMISSIONS.values())
        current = sum(self.DANGEROUS_PERMISSIONS.get(p, 5) for p in categorized["dangerous"])
        custom_score = len(categorized["custom"]) * 3
        ratio = (current + custom_score) / max_possible
        raw_score = min(100, ratio * 100)
        booster = 1.0
        if len(categorized["dangerous"]) >= 5:
            booster += 0.15
        if len(categorized["dangerous"]) >= 10:
            booster += 0.20
        if len(categorized["custom"]) > 0:
            booster += 0.10
        final = min(100, raw_score * booster)
        return {
            "score": round(final, 2),
            "raw_score": round(raw_score, 2),
            "dangerous_count": len(categorized["dangerous"]),
            "custom_count": len(categorized["custom"]),
            "total_permissions": sum(len(v) for v in categorized.values()),
            "booster_multiplier": round(booster, 2),
        }


class StringAnalyzer:
    """
    Extracts and analyzes strings from DEX bytecode.
    Detects URLs, IPs, domains, emails, and computes entropy.
    """

    URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+")
    IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    DOMAIN_PATTERN = re.compile(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}")
    EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
    BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
    HEX_PAYLOAD_PATTERN = re.compile(r"[0-9a-fA-F]{32,}")

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Compute Shannon entropy of a string (delegates to shared utility)."""
        return _shannon_entropy(data)

    @staticmethod
    def is_high_entropy(s: str, threshold: float = 4.5) -> bool:
        """Check if string entropy exceeds threshold."""
        return _is_high_entropy(s, threshold)

    def extract_all(self, strings: List[str]) -> Dict:
        """Extract and analyze all IOCs from a list of strings."""
        urls = []
        ips = []
        domains = []
        emails = []
        base64_candidates = []
        hex_payloads = []
        high_entropy = []
        for s in strings:
            urls.extend(self.URL_PATTERN.findall(s))
            ips.extend(self.IP_PATTERN.findall(s))
            emails.extend(self.EMAIL_PATTERN.findall(s))
            dm = self.DOMAIN_PATTERN.findall(s)
            for d in dm:
                if not d.startswith("http") and "." in d and not d.startswith("android."):
                    # Filter out version strings (e.g., "1.2.3.4")
                    if re.match(r'^\d+\.\d+\.\d+', d):
                        continue
                    # Filter out Java package names (e.g., "com.example.app")
                    if re.match(r'^(com|org|net|io|me|de|fr|uk|ru|cn|jp)\.', d):
                        continue
                    domains.append(d)
            b64 = self.BASE64_PATTERN.findall(s)
            base64_candidates.extend(b64)
            hex_payloads.extend(self.HEX_PAYLOAD_PATTERN.findall(s))
        urls = list(set(urls))
        ips = list(set(ips))
        domains = list(set(domains))
        emails = list(set(emails))
        base64_candidates = list(set(base64_candidates))
        hex_payloads = list(set(hex_payloads))
        for s in strings:
            if self.is_high_entropy(s) and len(s) > 8:
                ent = self.shannon_entropy(s)
                high_entropy.append({"value": s[:200], "entropy": ent, "length": len(s), "label": entropy_label(ent)})
        high_entropy.sort(key=lambda x: x["entropy"], reverse=True)
        return {
            "urls": urls,
            "ips": ips,
            "domains": domains,
            "emails": emails,
            "base64_candidates": base64_candidates,
            "hex_payloads": hex_payloads[:50],
            "high_entropy_strings": high_entropy[:50],
            "total_strings_analyzed": len(strings),
        }


class StaticAnalyzer:
    """
    Main static analysis engine for APK files.
    Orchestrates permission analysis, manifest extraction, DEX string analysis,
    certificate extraction, native library analysis, and anti-analysis detection.
    """

    ANTI_ANALYSIS_INDICATORS = {
        "emulator_check": [
            "ro.kernel.qemu", "ro.product.device", "generic",
            "google_sdk", "sdk_google", "genymotion", "test-keys",
            "ro.hardware", "goldfish", "ranchu",
        ],
        "debugger_detection": [
            "android.os.Debug.isDebuggerConnected",
            "debuggerConnected", "waitForDebugger",
            "android_server", "strace", "ptrace",
        ],
        "root_detection": [
            "su", "busybox", "superuser", "supersu",
            "magisk", "/system/app/Superuser",
            "which su", "test-root", "ro.debuggable",
        ],
        "proxy_detection": [
            "HTTP_PROXY", "HTTPS_PROXY", "proxy_host", "proxy_port",
            "System.getProperty.http.proxyHost",
            "System.getProperty.http.proxyPort",
        ],
        "obfuscation": [
            "Ljava/lang/reflect/Method;->invoke",
            "DexClassLoader",
            "PathClassLoader",
            "InMemoryDexClassLoader",
            "dalvik.system.DexFile",
            "DexPathList",
        ],
        "cert_pinning_bypass": [
            "X509TrustManager",
            "checkServerTrusted",
            "checkClientTrusted",
            "ALLOW_ALL_HOSTNAME",
            "AllowAllHostnameVerifier",
            "NullHostnameVerifier",
            "InsecureTrustManager",
            "TrustAllCerts",
            "sslSocketFactory",
            "hostnameVerifier",
        ],
    }

    SUSPICIOUS_NATIVE_FUNCTIONS = {
        "system(", "execvp(", "fork(", "ptrace(", "dlopen(", "dlsym(",
        "mmap(", "mprotect(", "popen(", "execve(", "kill(",
        "listen(", "bind(", "accept(",
        "socket(", "connect(", "send(", "sendto(", "recv(", "recvfrom(",
    }

    def __init__(self):
        self.perm_analyzer = PermissionAnalyzer()
        self.string_analyzer = StringAnalyzer()

    def analyze(self, apk_path: str) -> Dict:
        """
        Perform full static analysis on an APK file.

        Args:
            apk_path: Path to the APK file.

        Returns:
            Comprehensive analysis dictionary.
        """
        if not os.path.isfile(apk_path):
            return {"error": f"File not found: {apk_path}", "success": False}
        result = {
            "success": True,
            "file_info": self._get_file_info(apk_path),
            "manifest": {},
            "permissions": {},
            "dex_strings": {},
            "certificate": {},
            "native_libs": [],
            "anti_analysis": {},
            "permission_mappings": [],
            "raw_report": {},
        }
        try:
            apk, dex_strings, dex_classes, analysis_obj = self._load_apk(apk_path)
            if apk is None:
                return {**result, "success": False, "error": "Failed to parse APK"}
            result["manifest"] = self._extract_manifest(apk, dex_classes)
            result["permissions"] = self._analyze_permissions(apk)
            result["dex_strings"] = self._analyze_strings(dex_strings)
            result["certificate"] = self._extract_certificate(apk_path, apk)
            result["native_libs"] = self._analyze_native_libraries(apk)
            result["anti_analysis"] = self._detect_anti_analysis(dex_strings, result["manifest"])
            result["permission_mappings"] = self._map_permissions_to_code(apk, dex_classes, result["permissions"]["categorized"]["dangerous"], analysis_obj)
            result["raw_report"] = self._build_raw_report(result)
        except Exception as e:
            logger.exception("Static analysis failed")
            result["success"] = False
            result["error"] = str(e)
        return result

    def _get_file_info(self, apk_path: str) -> Dict:
        """Extract basic file metadata and hashes."""
        stat = os.stat(apk_path)
        info = {
            "file_name": os.path.basename(apk_path),
            "file_size_bytes": stat.st_size,
            "file_size_mb": round(stat.st_size / (1024 * 1024), 2),
            "md5": "",
            "sha1": "",
            "sha256": "",
        }
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            with open(apk_path, "rb") as f:
                while True:
                    chunk = f.read(65536)  # 64KB chunks
                    if not chunk:
                        break
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            info["md5"] = md5.hexdigest()
            info["sha1"] = sha1.hexdigest()
            info["sha256"] = sha256.hexdigest()
        except Exception as e:
            logger.error(f"Hash computation failed: {e}")
        return info

    def _load_apk(self, apk_path: str) -> Tuple[Optional[object], List[str], List[str], Optional[object]]:
        """
        Load APK using androguard or fallback to zipfile.
        Returns (APK_object, list_of_strings, list_of_class_names, analysis_object).
        """
        apk = None
        dex_strings = []
        dex_classes = []
        analysis_obj = None
        if ANDROGUARD_AVAILABLE:
            try:
                apk = APK(apk_path)
                dex = DalvikVMFormat(apk.get_dex())
                analysis_obj = Analysis(dex)
                dex_strings = list(dex.get_strings())
                dex_classes = [c.get_name() for c in dex.get_classes()]
                logger.info(f"Loaded {len(dex_strings)} strings, {len(dex_classes)} classes via androguard")
                return apk, dex_strings, dex_classes, analysis_obj
            except Exception as e:
                logger.warning(f"androguard parsing failed, falling back to zip: {e}")
        try:
            with zipfile.ZipFile(apk_path, "r") as zf:
                dex_files = [n for n in zf.namelist() if n.endswith(".dex")]
                for dex_name in dex_files:
                    raw = zf.read(dex_name)
                    text = self._extract_strings_from_dex_bytes(raw)
                    dex_strings.extend(text)
                apk = self._fallback_apk_from_zip(zf, apk_path)
                logger.info(f"Fallback parse: {len(dex_strings)} strings from {len(dex_files)} dex files")
        except Exception as e:
            logger.error(f"Fallback ZIP parse failed: {e}")
        return apk, list(set(dex_strings)), dex_classes, analysis_obj

    def _extract_strings_from_dex_bytes(self, raw: bytes) -> List[str]:
        """Naive string extraction from raw DEX bytes — finds printable sequences."""
        strings = []
        current = []
        for byte in raw:
            if 32 <= byte <= 126:
                current.append(chr(byte))
            else:
                if len(current) >= 4:
                    strings.append("".join(current))
                current = []
        if len(current) >= 4:
            strings.append("".join(current))
        return strings

    def _fallback_apk_from_zip(self, zf: zipfile.ZipFile, apk_path: str = "") -> Optional[object]:
        """Create a simple APK-like dict when androguard is unavailable."""
        class FallbackAPK:
            def __init__(self, archive, apk_file_path):
                self.archive = archive
                self._apk_file_path = apk_file_path
                self._manifest = archive.read("AndroidManifest.xml") if "AndroidManifest.xml" in archive.namelist() else b""
                self._permissions = []
                self._package = ""
                self._activities = []
                self._services = []
                self._receivers = []
                self._providers = []
                self._lib_files = [n for n in archive.namelist() if "lib/" in n and (".so" in n)]
                raw = self._manifest
                if not raw:
                    return
                decoded = self._decode_manifest(raw, apk_file_path)
                if not decoded:
                    return
                # Extract package name
                m = re.search(r'package="([^"]+)"', decoded)
                if not m:
                    # aapt output format: "package: name='com.example'"
                    m = re.search(r"package:\s*name='([^']+)'", decoded)
                if m:
                    self._package = m.group(1)
                # Extract permissions — handles both XML and aapt output formats
                self._permissions = re.findall(r'android:name="([^"]+\.permission\.[^"]+)"', decoded)
                if not self._permissions:
                    # aapt format: "uses-permission: name='android.permission.X'"
                    self._permissions = re.findall(r"uses-permission:\s*name='([^']+)'", decoded)
                self._activities = re.findall(r'<activity[^>]+android:name="([^"]+)"', decoded)
                if not self._activities:
                    self._activities = re.findall(r"activity(?:-alias)?\s+name='([^']+)'", decoded)
                self._services = re.findall(r'<service[^>]+android:name="([^"]+)"', decoded)
                if not self._services:
                    self._services = re.findall(r"service\s+name='([^']+)'", decoded)
                self._receivers = re.findall(r'<receiver[^>]+android:name="([^"]+)"', decoded)
                if not self._receivers:
                    self._receivers = re.findall(r"receiver\s+name='([^']+)'", decoded)
                self._providers = re.findall(r'<provider[^>]+android:name="([^"]+)"', decoded)
                if not self._providers:
                    self._providers = re.findall(r"provider\s+name='([^']+)'", decoded)

            @staticmethod
            def _decode_manifest(raw: bytes, apk_file_path: str = "") -> str:
                """Attempt to decode binary XML manifest to readable XML string."""
                # Strategy 1: Try androguard's AXML parser (may work even if full APK parsing failed)
                try:
                    from androguard.core.bytecodes.axml import AXMLPrinter
                    axml = AXMLPrinter(raw)
                    xml_bytes = axml.get_xml()
                    if isinstance(xml_bytes, bytes):
                        result = xml_bytes.decode("utf-8", errors="replace")
                    else:
                        result = str(xml_bytes)
                    if result and "<" in result:
                        return result
                except Exception:
                    pass
                # Strategy 2: Use aapt to dump the manifest from the original APK file
                if apk_file_path and os.path.isfile(apk_file_path):
                    try:
                        from config import settings
                        result = subprocess.run(
                            [settings.AAPT_PATH, "dump", "xmltree", apk_file_path, "AndroidManifest.xml"],
                            capture_output=True, text=True, timeout=30,
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            return result.stdout
                    except Exception:
                        pass
                    # Strategy 2b: aapt dump badging (more concise but has package/permissions)
                    try:
                        from config import settings
                        result = subprocess.run(
                            [settings.AAPT_PATH, "dump", "badging", apk_file_path],
                            capture_output=True, text=True, timeout=30,
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            return result.stdout
                    except Exception:
                        pass
                # Strategy 3: Last resort — try UTF-8 decode (works for plaintext manifests)
                decoded = raw.decode("utf-8", errors="replace")
                if "<" in decoded:
                    return decoded
                return ""

            def get_permissions(self):
                return self._permissions
            def get_package(self):
                return self._package
            def get_android_manifest_axml(self):
                return self._manifest
            def get_activities(self):
                return self._activities
            def get_services(self):
                return self._services
            def get_receivers(self):
                return self._receivers
            def get_providers(self):
                return self._providers
            def get_files(self):
                return self.archive.namelist()
            def get_filename(self):
                return self._apk_file_path
        return FallbackAPK(zf, apk_path)

    def _extract_manifest(self, apk, dex_classes: List[str]) -> Dict:
        """Extract manifest metadata and component definitions."""
        manifest = {
            "package": "",
            "version_name": "",
            "version_code": "",
            "min_sdk": "",
            "target_sdk": "",
            "debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
        }
        try:
            if hasattr(apk, "get_package"):
                manifest["package"] = apk.get_package() or ""
            if hasattr(apk, "get_android_manifest_axml"):
                axml = apk.get_android_manifest_axml()
                if axml:
                    raw_xml = axml
                    if hasattr(axml, "get_xml"):
                        raw_xml = axml.get_xml()
                    elif hasattr(axml, "get") and callable(axml.get):
                        raw_xml = axml.get()

                    raw_str = raw_xml if isinstance(raw_xml, str) else (raw_xml.decode("utf-8", errors="replace") if isinstance(raw_xml, bytes) else str(raw_xml))
                    manifest["version_name"] = self._extract_attr(raw_str, "versionName") or ""
                    manifest["version_code"] = self._extract_attr(raw_str, "versionCode") or ""
                    manifest["min_sdk"] = self._extract_attr(raw_str, "minSdkVersion") or ""
                    manifest["target_sdk"] = self._extract_attr(raw_str, "targetSdkVersion") or ""
                    manifest["debuggable"] = self._extract_attr(raw_str, "debuggable") == "true"
                    manifest["allow_backup"] = self._extract_attr(raw_str, "allowBackup") == "true"
                    manifest["uses_cleartext_traffic"] = self._extract_attr(raw_str, "usesCleartextTraffic") == "true"
                    manifest["activities"] = self._extract_components_with_details(raw_str, "activity")
                    manifest["services"] = self._extract_components_with_details(raw_str, "service")
                    manifest["receivers"] = self._extract_components_with_details(raw_str, "receiver")
                    manifest["providers"] = self._extract_components_with_details(raw_str, "provider")
        except Exception as e:
            logger.warning(f"Manifest extraction error: {e}")
        try:
            if hasattr(apk, "get_min_sdk_version"):
                m = apk.get_min_sdk_version()
                if m:
                    manifest["min_sdk"] = str(m)
            if hasattr(apk, "get_target_sdk_version"):
                t = apk.get_target_sdk_version()
                if t:
                    manifest["target_sdk"] = str(t)
        except Exception:
            pass
        raw_str_lower = str(manifest).lower()
        if "android:debuggable=\"true\"" in raw_str_lower:
            manifest["debuggable"] = True
        return manifest

    def _extract_attr(self, xml: str, attr: str) -> str:
        """Extract a single attribute value from Android XML string."""
        patterns = [
            rf'{attr}="([^"]*)"',
            rf"android:{attr}='([^']*)'",
            rf"android:{attr}=([^\"'\s>]+)",
        ]
        for pat in patterns:
            m = re.search(pat, xml)
            if m:
                return m.group(1)
        return ""

    def _extract_components_with_details(self, xml: str, tag: str) -> List[Dict]:
        """Extract component definitions with exported flags and intent-filters."""
        components = []
        pattern = rf'<{tag}[^>]*/>'
        block_pattern = rf'<{tag}([^>]*)>(.*?)</{tag}>'
        for match in re.finditer(block_pattern, xml, re.DOTALL):
            attrs_str = match.group(1)
            body = match.group(2)
            name = self._extract_attr(attrs_str + body, "name")
            exported = self._extract_attr(attrs_str, "exported")
            intent_filters = re.findall(r'<action\s+android:name="([^"]+)"', body)
            comp = {
                "name": name,
                "exported": exported if exported else "default",
                "intent_filters": intent_filters,
            }
            components.append(comp)
        for match in re.finditer(pattern, xml):
            attrs_str = match.group(0)
            name = self._extract_attr(attrs_str, "name")
            exported = self._extract_attr(attrs_str, "exported")
            if name:
                comp = {
                    "name": name,
                    "exported": exported if exported else "default",
                    "intent_filters": [],
                }
                components.append(comp)
        return components

    def _analyze_permissions(self, apk) -> Dict:
        """Analyze permissions: categorize, risk score, and flag dangerous combos."""
        all_perms = []
        try:
            if hasattr(apk, "get_permissions"):
                all_perms = apk.get_permissions() or []
            elif hasattr(apk, "_permissions"):
                all_perms = apk._permissions
        except Exception as e:
            logger.error(f"Permission extraction failed: {e}")
        categorized = self.perm_analyzer.categorize_permissions(all_perms)
        risk = self.perm_analyzer.calculate_risk_score(categorized)
        dangerous_combos = []
        danger_set = set(categorized["dangerous"])
        sms_set = {"android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"}
        loc_set = {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}
        mic_cam = {"android.permission.RECORD_AUDIO", "android.permission.CAMERA"}
        if sms_set.issubset(danger_set):
            dangerous_combos.append("sms_related")
        if loc_set.issubset(danger_set):
            dangerous_combos.append("location_tracking")
        if mic_cam.issubset(danger_set):
            dangerous_combos.append("mic_camera")
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in danger_set:
            dangerous_combos.append("accessibility_service_abuse")
        if "android.permission.INSTALL_PACKAGES" in danger_set and "android.permission.REQUEST_INSTALL_PACKAGES" in danger_set:
            dangerous_combos.append("sideloading_capable")
        return {
            "all_permissions": all_perms,
            "categorized": categorized,
            "risk_score": risk,
            "dangerous_combinations": dangerous_combos,
        }

    def _analyze_strings(self, dex_strings: List[str]) -> Dict:
        """Extract IOCs and analyze strings from DEX."""
        return self.string_analyzer.extract_all(dex_strings)

    def _extract_certificate(self, apk_path: str, apk) -> Dict:
        """Extract certificate information using apksigner."""
        cert_info = {
            "signer": "",
            "digest": "",
            "certificate": {},
            "raw_output": "",
        }
        try:
            result = subprocess.run(
                ["apksigner", "verify", "--print-certs", apk_path],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                cert_info["raw_output"] = result.stdout.strip()
                for line in lines:
                    line_lower = line.lower()
                    if "signer" in line_lower:
                        cert_info["signer"] = line
                    elif "sha-256" in line_lower or "sha256" in line_lower or "digest" in line_lower:
                        cert_info["digest"] = line.split(":")[-1].strip() if ":" in line else line
                    elif "dn:" in line_lower or "subject:" in line_lower:
                        cert_info["certificate"]["subject"] = line.split(":")[-1].strip() if ":" in line else line
                    elif "issuer:" in line_lower:
                        cert_info["certificate"]["issuer"] = line.split(":")[-1].strip() if ":" in line else line
                    elif "valid" in line_lower:
                        cert_info["certificate"]["validity"] = line
            else:
                cert_info["raw_output"] = result.stderr
                logger.warning(f"apksigner failed: {result.stderr}")
        except FileNotFoundError:
            logger.warning("apksigner not found in PATH — skipping certificate extraction")
            try:
                if hasattr(apk, "get_certificate") or hasattr(apk, "get_signature_name"):
                    cert_info["note"] = "apksigner not available; using androguard fallback"
            except Exception:
                pass
        except subprocess.TimeoutExpired:
            logger.warning("apksigner timed out")
        except Exception as e:
            logger.error(f"Certificate extraction error: {e}")
        return cert_info

    def _analyze_native_libraries(self, apk) -> List[Dict]:
        """Find and analyze native .so libraries for suspicious functions."""
        libs = []
        lib_files = []
        try:
            if hasattr(apk, "get_files"):
                lib_files = [f for f in (apk.get_files() or []) if f.endswith(".so")]
            elif hasattr(apk, "_lib_files"):
                lib_files = apk._lib_files
        except Exception:
            pass
        for lib_rel_path in lib_files:
            lib_name = os.path.basename(lib_rel_path)
            entry = {
                "path": lib_rel_path,
                "name": lib_name,
                "arch": self._detect_arch(lib_rel_path),
                "suspicious_functions": [],
            }
            raw = b""
            try:
                if hasattr(apk, "get_file"):
                    raw = apk.get_file(lib_rel_path) or b""
            except Exception:
                pass
            if not raw:
                try:
                    with zipfile.ZipFile(self._get_apk_path_from_apk(apk), "r") as zf:
                        if lib_rel_path in zf.namelist():
                            raw = zf.read(lib_rel_path)
                except Exception:
                    pass
            if raw:
                found = self._find_native_suspicious(raw)
                entry["suspicious_functions"] = found
                entry["entropy"] = _shannon_entropy(raw)
                entry["entropy_label"] = entropy_label(entry["entropy"])
            libs.append(entry)
        return libs

    def _get_apk_path_from_apk(self, apk) -> str:
        if hasattr(apk, "get_filename"):
            return apk.get_filename() or ""
        return ""

    def _detect_arch(self, path: str) -> str:
        path_lower = path.lower()
        if "armeabi-v7a" in path_lower:
            return "armeabi-v7a"
        if "arm64-v8a" in path_lower:
            return "arm64-v8a"
        if "x86_64" in path_lower:
            return "x86_64"
        if "x86" in path_lower:
            return "x86"
        return "unknown"

    def _find_native_suspicious(self, raw: bytes) -> List[Dict]:
        """
        Extract readable strings from native code and check for suspicious functions.
        Uses exact string matching against known suspicious C function signatures.
        """
        strings = self._extract_strings_from_dex_bytes(raw)
        suspicious = []
        for func in self.SUSPICIOUS_NATIVE_FUNCTIONS:
            matches = [s for s in strings if func in s]
            if matches:
                suspicious.append({
                    "function": func.rstrip("("),
                    "occurrences": len(matches),
                    "examples": matches[:5],
                })
        return suspicious

    def _detect_anti_analysis(self, dex_strings: List[str], manifest: Dict) -> Dict:
        """Detect anti-analysis techniques by searching strings and manifest."""
        results = {}
        for technique, indicators in self.ANTI_ANALYSIS_INDICATORS.items():
            found = []
            for ind in indicators:
                # Use word-boundary matching to avoid false positives (e.g., "su" matching "issue")
                pattern = re.compile(r'\b' + re.escape(ind.lower()) + r'\b', re.IGNORECASE) if len(ind) <= 4 else None
                for s in dex_strings:
                    if pattern:
                        if pattern.search(s):
                            context = self._extract_context(dex_strings, ind)
                            found.append({"indicator": ind, "context": context[:3]})
                            break
                    else:
                        if ind.lower() in s.lower():
                            context = self._extract_context(dex_strings, ind)
                            found.append({"indicator": ind, "context": context[:3]})
                            break
            if manifest.get("debuggable"):
                if technique == "debugger_detection":
                    found.append({"indicator": "android:debuggable=true in manifest", "context": []})
            results[technique] = {
                "detected": len(found) > 0,
                "count": len(found),
                "indicators": found,
            }
        anti_analysis_score = 0
        for tech, data in results.items():
            if data["detected"]:
                anti_analysis_score += min(25, data["count"] * 5)
        results["overall"] = {
            "detected_any": any(v["detected"] for k, v in results.items() if k != "overall"),
            "total_indicators": sum(v["count"] for k, v in results.items() if k != "overall"),
            "score": min(100, anti_analysis_score),
        }
        return results

    def _extract_context(self, strings: List[str], indicator: str, window: int = 5) -> List[str]:
        """Extract surrounding context for a matched indicator."""
        contexts = []
        for i, s in enumerate(strings):
            if indicator.lower() in s.lower():
                start = max(0, i - window)
                end = min(len(strings), i + window + 1)
                snippet = " ... ".join(strings[start:end])
                contexts.append(snippet[:200])
                if len(contexts) >= 3:
                    break
        return contexts

    def _map_permissions_to_code(self, apk, dex_classes: List[str], dangerous_perms: List[str], analysis_obj=None) -> List[Dict]:
        """
        Map dangerous permissions to potential code paths.
        Searches class names and method references for permission-related patterns.
        """
        mappings = []
        try:
            if ANDROGUARD_AVAILABLE and hasattr(apk, "get_dex"):
                analysis = analysis_obj if analysis_obj is not None else Analysis(DalvikVMFormat(apk.get_dex()))
                for cls in analysis.get_classes():
                    cls_name = cls.get_name() if hasattr(cls, "get_name") else str(cls)
                    for method in cls.get_methods():
                        meth_name = method.get_name() if hasattr(method, "get_name") else ""
                        full_method = f"{cls_name}->{meth_name}"
                        for perm in dangerous_perms:
                            perm_short = perm.split(".")[-1].lower()
                            code = str(method.get_code()) if hasattr(method, "get_code") else ""
                            if perm_short in meth_name.lower() or perm_short in code.lower():
                                mappings.append({
                                    "class": cls_name,
                                    "method": meth_name,
                                    "permission": perm,
                                })
        except Exception as e:
            logger.debug(f"Permission mapping error (non-fatal): {e}")
            for cls_name in dex_classes[:50]:
                for perm in dangerous_perms[:5]:
                    perm_short = perm.split(".")[-1].lower()
                    if perm_short in cls_name.lower():
                        mappings.append({
                            "class": cls_name,
                            "method": "unknown",
                            "permission": perm,
                        })
        return mappings

    def _build_raw_report(self, result: Dict) -> Dict:
        """Build a concise raw text report for evidence."""
        lines = []
        fi = result.get("file_info", {})
        lines.append(f"File: {fi.get('file_name', 'N/A')}")
        lines.append(f"Size: {fi.get('file_size_mb', 0)} MB")
        lines.append(f"SHA256: {fi.get('sha256', 'N/A')}")
        mf = result.get("manifest", {})
        lines.append(f"Package: {mf.get('package', 'N/A')}")
        lines.append(f"Min SDK: {mf.get('min_sdk', 'N/A')}  Target: {mf.get('target_sdk', 'N/A')}")
        lines.append(f"Debuggable: {mf.get('debuggable', False)}  Backup: {mf.get('allow_backup', False)}")
        perm = result.get("permissions", {})
        rscore = perm.get("risk_score", {})
        lines.append(f"Permission Risk: {rscore.get('score', 0)}/100  Dangerous: {rscore.get('dangerous_count', 0)}")
        ds = result.get("dex_strings", {})
        lines.append(f"URLs: {len(ds.get('urls', []))}  IPs: {len(ds.get('ips', []))}  Domains: {len(ds.get('domains', []))}")
        lines.append(f"High Entropy: {len(ds.get('high_entropy_strings', []))}")
        aa = result.get("anti_analysis", {}).get("overall", {})
        lines.append(f"Anti-Analysis Score: {aa.get('score', 0)}/100  Detected: {aa.get('detected_any', False)}")
        lines.append(f"Native Libraries: {len(result.get('native_libs', []))}")
        return {"text": "\n".join(lines)}
