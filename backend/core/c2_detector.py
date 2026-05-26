"""
C2 (Command & Control) Detection Engine.
Analyzes static analysis results to detect C2 infrastructure, DGA domains,
beaconing behavior, and maps findings to MITRE ATT&CK for Mobile.
"""
import logging
import re
from typing import Dict, List, Optional, Tuple
from utils.entropy import shannon_entropy as _shannon_entropy

logger = logging.getLogger(__name__)


class DGADetector:
    """
    Detects Domain Generation Algorithm (DGA) domains.
    DGA domains often have high entropy, unusual consonant/vowel ratios,
    and are longer than normal domains.
    """

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Compute Shannon entropy of a string (delegates to shared utility)."""
        return _shannon_entropy(data)

    @staticmethod
    def consonant_vowel_ratio(s: str) -> float:
        """Compute consonant-to-vowel ratio (vowels: aeiou)."""
        s = s.lower()
        vowels = sum(1 for c in s if c in "aeiou")
        consonants = len(s) - vowels
        if vowels == 0:
            return float("inf")
        return consonants / vowels

    @staticmethod
    def unique_char_count(s: str) -> int:
        """Count unique characters in the string."""
        return len(set(s))

    @staticmethod
    def is_likely_dga(domain: str) -> Dict:
        """
        Evaluate whether a domain is likely DGA-generated.

        Returns dict with score and contributing factors.
        """
        domain_clean = domain.split(".")[0] if "." in domain else domain
        entropy = DGADetector.shannon_entropy(domain_clean)
        cv_ratio = DGADetector.consonant_vowel_ratio(domain_clean)
        unique_chars = DGADetector.unique_char_count(domain_clean)
        length = len(domain_clean)

        # Check if domain parts look like real words (reduces false positives on legitimate long domains)
        parts = re.split(r'[-_.]', domain_clean)
        real_word_parts = 0
        for part in parts:
            if len(part) >= 3:
                part_vowels = sum(1 for c in part.lower() if c in "aeiou")
                part_ratio = part_vowels / len(part) if len(part) > 0 else 0
                if 0.2 <= part_ratio <= 0.6:  # reasonable vowel ratio = likely a word
                    real_word_parts += 1
        looks_like_words = real_word_parts >= len([p for p in parts if len(p) >= 3]) * 0.5 and real_word_parts > 0

        # TLD penalty: legitimate TLDs get a penalty
        trusted_tlds = {'.gov', '.edu', '.org', '.mil'}
        tld_penalty = 0
        for tld in trusted_tlds:
            if domain.endswith(tld):
                tld_penalty = -15
                break

        score = 0
        reasons = []

        # Higher entropy threshold (4.3 instead of 4.0) to reduce FPs
        if entropy > 4.3:
            score += 25
            reasons.append(f"high_entropy ({entropy:.2f})")
        if cv_ratio > 5.0 and not looks_like_words:
            score += 25
            reasons.append(f"high_cv_ratio ({cv_ratio:.2f})")
        if length > 20 and not looks_like_words:
            score += 20
            reasons.append(f"long_domain ({length} chars)")
        if unique_chars > 12 and not looks_like_words:
            score += 15
            reasons.append(f"high_unique_chars ({unique_chars})")
        if cv_ratio == float("inf") and length > 6:
            score += 10
            reasons.append("no_vowels")
        # Only flag long number sequences that are NOT year-like (4 digits) or IP-like
        num_match = re.search(r'(\d{5,})', domain_clean)
        if num_match:
            score += 5
            reasons.append("contains_long_number_sequence")

        score = max(0, score + tld_penalty)

        return {
            "domain": domain,
            "entropy": entropy,
            "cv_ratio": round(cv_ratio, 2) if cv_ratio != float("inf") else 999.0,
            "length": length,
            "unique_chars": unique_chars,
            "dga_score": min(100, score),
            "is_suspicious": score >= 40,
            "reasons": reasons,
        }


class BeaconingDetector:
    """
    Detects beaconing patterns in decompiled code.
    Looks for periodic task scheduling and timing patterns.
    """

    BEACON_PATTERNS = {
        "timer": [
            "Timer", "TimerTask", "schedule", "scheduleAtFixedRate",
            "Handler.postDelayed", "Handler.sendMessageDelayed",
            "ScheduledExecutorService", "scheduleWithFixedDelay",
        ],
        "alarm": [
            "AlarmManager", "setRepeating", "setInexactRepeating",
            "setAlarmClock", "setExact", "setWindow",
        ],
        "job_scheduler": [
            "JobScheduler", "JobService", "schedule",
            "setPeriodic", "setOverrideDeadline",
        ],
        "thread_sleep": [
            "Thread.sleep", "SystemClock.sleep",
        ],
        "work_manager": [
            "WorkManager", "PeriodicWorkRequest", "PeriodicWork",
            "setInitialDelay", "enqueueUniquePeriodicWork",
        ],
    }

    SUSPICIOUS_BEACON_INTERVALS = [
        30000, 60000, 120000, 300000, 600000,
        3600000, 1800000, 900000, 45000, 15000,
    ]

    @staticmethod
    def detect(dex_strings: List[str]) -> Dict:
        """Search decompiled strings for periodic communication patterns."""
        results = {}
        total_hits = 0
        combined = " ".join(dex_strings)
        for category, patterns in BeaconingDetector.BEACON_PATTERNS.items():
            found = []
            for pat in patterns:
                if pat.lower() in combined.lower():
                    found.append(pat)
                    total_hits += 1
            results[category] = {
                "detected": len(found) > 0,
                "count": len(found),
                "patterns_found": found,
            }

        interval_matches = []
        for interval in BeaconingDetector.SUSPICIOUS_BEACON_INTERVALS:
            interval_str = str(interval)
            if interval_str in combined:
                interval_matches.append(interval)
        results["suspicious_intervals_ms"] = interval_matches

        results["overall"] = {
            "beaconing_detected": total_hits > 0,
            "total_indicators": total_hits,
            "score": min(100, total_hits * 12),
        }
        return results


class IOCMatcher:
    """
    Matches extracted IOCs against a known malicious IOC database.
    Supports both flat list format and dict format {"urls": [...], "domains": [...], "ips": [...], "hashes": [...]}.
    """

    def __init__(self, ioc_db=None):
        self.url_iocs = set()
        self.domain_iocs = set()
        self.ip_iocs = set()
        self.hash_iocs = set()
        if ioc_db:
            self.set_ioc_database(ioc_db)

    def set_ioc_database(self, iocs):
        """Set or update the IOC database. Accepts dict or list."""
        if isinstance(iocs, dict):
            self.url_iocs = set(iocs.get("urls", []))
            self.domain_iocs = set(iocs.get("domains", []))
            self.ip_iocs = set(iocs.get("ips", []))
            self.hash_iocs = set(iocs.get("hashes", []))
        elif isinstance(iocs, list):
            # Legacy flat list — put everything in a general set
            self.url_iocs = set(iocs)
            self.domain_iocs = set(iocs)
            self.ip_iocs = set(iocs)

    def match_urls(self, urls: List[str]) -> List[Dict]:
        """Match URLs against IOC database (partial and exact)."""
        matches = []
        for url in urls:
            url_lower = url.lower()
            for ioc in self.url_iocs:
                if len(ioc) >= 6 and ioc.lower() in url_lower:
                    matches.append({"ioc": ioc, "matched": url, "type": "url"})
                    break
        return matches

    def match_domains(self, domains: List[str]) -> List[Dict]:
        """Match domains against IOC database."""
        matches = []
        for domain in domains:
            domain_clean = domain.lower().strip()
            for ioc in self.domain_iocs:
                ioc_clean = ioc.lower().strip()
                if len(ioc_clean) >= 4 and (domain_clean == ioc_clean or domain_clean.endswith("." + ioc_clean) or ioc_clean.endswith("." + domain_clean)):
                    matches.append({"ioc": ioc, "matched": domain, "type": "domain"})
                    break
        return matches

    def match_ips(self, ips: List[str]) -> List[Dict]:
        """Match IPs against IOC database (exact match)."""
        matches = []
        for ip in ips:
            if ip in self.ip_iocs:
                matches.append({"ioc": ip, "matched": ip, "type": "ip"})
        return matches

    def match_all(self, urls: List[str], domains: List[str], ips: List[str]) -> Dict:
        """Run all matchers and return combined results."""
        url_matches = self.match_urls(urls)
        domain_matches = self.match_domains(domains)
        ip_matches = self.match_ips(ips)
        return {
            "url_matches": url_matches,
            "domain_matches": domain_matches,
            "ip_matches": ip_matches,
            "total_matches": len(url_matches) + len(domain_matches) + len(ip_matches),
        }


class C2Detector:
    """
    C2 Detection Engine. Takes static analysis results and produces
    a comprehensive C2 threat assessment.
    """

    SUSPICIOUS_PORTS = [4444, 8080, 1337, 6666, 5555, 8888, 9999, 2222, 4443, 8443, 9001, 31337, 12345, 54321]

    KNOWN_MALICIOUS_IP_RANGES = {
        "185.130.5.0/24": "RU",
        "91.121.0.0/16": "FR",
        "5.196.0.0/16": "FR",
        "46.105.0.0/16": "FR",
        "103.235.0.0/16": "CN",
        "45.33.0.0/16": "US",
        "23.129.64.0/24": "US",
        "198.98.0.0/16": "US",
        "107.189.0.0/16": "LU",
        "185.165.0.0/16": "NL",
        "194.26.0.0/16": "RU",
        "176.123.0.0/16": "RU",
        "195.22.0.0/16": "RU",
        "84.38.0.0/16": "UA",
        "154.47.0.0/16": "NL",
        "45.67.0.0/16": "NL",
        "91.92.0.0/16": "NL",
        "141.98.0.0/16": "DE",
        "91.240.0.0/16": "US",
        "89.248.0.0/16": "NL",
    }

    def __init__(self, ioc_db: Optional[List[str]] = None):
        self.dga_detector = DGADetector()
        self.beaconing_detector = BeaconingDetector()
        self.ioc_matcher = IOCMatcher(ioc_db)

    def set_ioc_database(self, iocs: List[str]):
        self.ioc_matcher.set_ioc_database(iocs)

    def analyze(self, static_results: dict) -> Dict:
        """
        Perform C2 analysis on static analysis results.

        Args:
            static_results: Output dict from StaticAnalyzer.analyze()

        Returns:
            Comprehensive C2 analysis dictionary.
        """
        result = {
            "dga_analysis": [],
            "beaconing_analysis": {},
            "ioc_matches": {},
            "suspicious_ports": [],
            "raw_socket_usage": False,
            "encrypted_dns_usage": False,
            "geolocation": [],
            "mitre_mappings": [],
            "overall_score": 0,
            "summary": "",
        }

        try:
            dex_strings = static_results.get("dex_strings", {})
            urls = dex_strings.get("urls", [])
            ips = dex_strings.get("ips", [])
            domains = dex_strings.get("domains", [])
            high_entropy = dex_strings.get("high_entropy_strings", [])
            all_strings_raw = static_results.get("raw_report", {}).get("text", "")

            result["dga_analysis"] = self._analyze_dga(domains, urls)

            # Use ALL strings for beaconing (not just high-entropy) when available
            all_strings_for_beaconing = static_results.get("_all_strings_for_beaconing")
            if all_strings_for_beaconing:
                beaconing_input = {"high_entropy_strings": all_strings_for_beaconing}
                result["beaconing_analysis"] = self._analyze_beaconing(beaconing_input)
            else:
                result["beaconing_analysis"] = self._analyze_beaconing(dex_strings)

            result["ioc_matches"] = self._analyze_iocs(urls, domains, ips)
            result["suspicious_ports"] = self._detect_suspicious_ports(all_strings_raw, dex_strings)
            result["raw_socket_usage"] = self._detect_raw_sockets(all_strings_raw)
            result["encrypted_dns_usage"] = self._detect_encrypted_dns(all_strings_raw)
            result["geolocation"] = self._geolocate_ips(ips)
            result["mitre_mappings"] = self._map_to_mitre(result)
            result["overall_score"] = self._calculate_c2_score(result)
            result["summary"] = self._generate_summary(result)
        except Exception as e:
            logger.exception("C2 analysis failed")
            result["error"] = str(e)

        return result

    def _analyze_dga(self, domains: List[str], urls: List[str]) -> List[Dict]:
        """Analyze all domains and URL hostnames for DGA characteristics."""
        all_domains = set(domains)
        for url in urls:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                hostname = parsed.hostname or ""
                if hostname:
                    all_domains.add(hostname)
            except Exception:
                pass
        results = []
        for domain in sorted(all_domains):
            if not domain or domain.startswith("android."):
                continue
            analysis = self.dga_detector.is_likely_dga(domain)
            if analysis["is_suspicious"]:
                results.append(analysis)
        results.sort(key=lambda x: x["dga_score"], reverse=True)
        return results

    def _analyze_beaconing(self, dex_strings: Dict) -> Dict:
        """Run beaconing detection."""
        strings_list = dex_strings.get("high_entropy_strings", [])
        raw_values = [s["value"] if isinstance(s, dict) else s for s in (strings_list if isinstance(strings_list, list) else [])]
        return self.beaconing_detector.detect(raw_values)

    def _analyze_iocs(self, urls: List[str], domains: List[str], ips: List[str]) -> Dict:
        """Run IOC matching against the database."""
        matches = self.ioc_matcher.match_all(urls, domains, ips)
        total = len(matches["url_matches"]) + len(matches["domain_matches"]) + len(matches["ip_matches"])
        matches["total_matches"] = total
        return matches

    def _detect_suspicious_ports(self, all_strings_raw: str, dex_strings: Dict) -> List[Dict]:
        """Find references to suspicious ports in decompiled code."""
        found = []
        seen_ports = set()
        for port in self.SUSPICIOUS_PORTS:
            port_str = str(port)
            # Only match port in host:port context (not in URLs, version strings, etc.)
            port_pattern = re.compile(r'[:\s]' + re.escape(port_str) + r'\b')
            if port_pattern.search(all_strings_raw) and port not in seen_ports:
                seen_ports.add(port)
                context = ""
                match = port_pattern.search(all_strings_raw)
                if match:
                    idx = match.start()
                    start = max(0, idx - 30)
                    end = min(len(all_strings_raw), idx + 40)
                    context = all_strings_raw[start:end]
                found.append({"port": port, "context": context[:80]})
        return found

    def _detect_raw_sockets(self, all_strings_raw: str) -> bool:
        """Detect raw socket usage indicators (only class instantiations, not common getters)."""
        patterns = [
            "java.net.Socket(", "java.net.DatagramSocket(",
            "java.net.ServerSocket(", "new Socket(", "new DatagramSocket(",
            "new ServerSocket(", "InetSocketAddress(",
            "DatagramPacket(",
        ]
        return any(p in all_strings_raw for p in patterns)

    def _detect_encrypted_dns(self, all_strings_raw: str) -> bool:
        """Detect DNS-over-HTTPS usage."""
        patterns = [
            "dns.google/dns-query", "cloudflare-dns.com/dns-query",
            "quad9.net/dns-query", "application/dns-message",
            "DnsOverHttps", "dns-over-https",
            "okhttp3.dns.DnsOverHttps", "dnsjava",
        ]
        return any(p.lower() in all_strings_raw.lower() for p in patterns)

    def _geolocate_ips(self, ips: List[str]) -> List[Dict]:
        """Map IPs to geographic locations using the known malicious ranges."""
        results = []
        for ip in ips:
            if ip.startswith("127.") or ip == "0.0.0.0":
                continue
            country = self._ip_to_country(ip)
            if country:
                results.append({"ip": ip, "country": country, "is_local": country == "Local"})
            else:
                results.append({"ip": ip, "country": "Unknown", "is_local": False})
        return results

    def _ip_to_country(self, ip: str) -> Optional[str]:
        """Simple IP-to-country lookup using hardcoded CIDR ranges."""
        try:
            ip_int = self._ip_to_int(ip)
            if ip_int is None:
                return None
            for cidr, country in self.KNOWN_MALICIOUS_IP_RANGES.items():
                if self._ip_in_cidr(ip_int, cidr):
                    return country
        except Exception:
            pass
        return None

    @staticmethod
    def _ip_to_int(ip: str) -> Optional[int]:
        """Convert dotted-quad IP to integer."""
        try:
            parts = [int(x) for x in ip.split(".")]
            if len(parts) != 4:
                return None
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _ip_in_cidr(ip_int: int, cidr: str) -> bool:
        """Check if an IP integer falls within a CIDR range."""
        try:
            network, bits = cidr.split("/")
            bits = int(bits)
            net_int = C2Detector._ip_to_int(network)
            if net_int is None:
                return False
            mask = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
            return (ip_int & mask) == (net_int & mask)
        except Exception:
            return False

    def _map_to_mitre(self, c2_result: Dict) -> List[Dict]:
        """Map findings to MITRE ATT&CK for Mobile techniques."""
        mappings = []

        if c2_result.get("dga_analysis"):
            mappings.append({
                "technique": "T1568.002 - Domain Generation Algorithms",
                "tactic": "Command and Control",
                "detected": True,
                "evidence": f"{len(c2_result['dga_analysis'])} suspicious DGA domains found",
            })

        if c2_result.get("beaconing_analysis", {}).get("overall", {}).get("beaconing_detected"):
            mappings.append({
                "technique": "T1071.001 - Application Layer Protocol: Web Protocols",
                "tactic": "Command and Control",
                "detected": True,
                "evidence": "Beaconing patterns detected in decompiled code",
            })

        if c2_result.get("suspicious_ports"):
            mappings.append({
                "technique": "T1571 - Non-Standard Port",
                "tactic": "Command and Control",
                "detected": True,
                "evidence": f"Suspicious ports found: {[p['port'] for p in c2_result['suspicious_ports']]}",
            })

        if c2_result.get("raw_socket_usage"):
            mappings.append({
                "technique": "T1573.001 - Encrypted Channel: Symmetric Cryptography",
                "tactic": "Command and Control",
                "detected": True,
                "evidence": "Raw socket usage detected (Socket/DatagramSocket)",
            })

        if c2_result.get("ioc_matches", {}).get("total_matches", 0) > 0:
            mappings.append({
                "technique": "T1587.001 - Develop Capabilities: Malware",
                "tactic": "Resource Development",
                "detected": True,
                "evidence": f"{c2_result['ioc_matches']['total_matches']} IOCs matched known malicious indicators",
            })

        if c2_result.get("encrypted_dns_usage"):
            mappings.append({
                "technique": "T1572 - Protocol Tunneling",
                "tactic": "Command and Control",
                "detected": True,
                "evidence": "Encrypted DNS (DoH) usage detected",
            })

        if not mappings:
            mappings.append({
                "technique": "None Detected",
                "tactic": "N/A",
                "detected": False,
                "evidence": "No MITRE ATT&CK techniques identified",
            })

        return mappings

    def _calculate_c2_score(self, c2_result: Dict) -> int:
        """Calculate an overall C2 threat score (0-100)."""
        score = 0

        dga_count = len(c2_result.get("dga_analysis", []))
        score += min(30, dga_count * 8)

        beaconing = c2_result.get("beaconing_analysis", {}).get("overall", {})
        if beaconing.get("beaconing_detected"):
            score += min(20, beaconing.get("total_indicators", 0) * 5)

        ioc_total = c2_result.get("ioc_matches", {}).get("total_matches", 0)
        score += min(25, ioc_total * 10)

        port_count = len(c2_result.get("suspicious_ports", []))
        score += min(15, port_count * 5)

        if c2_result.get("raw_socket_usage"):
            score += 10

        if c2_result.get("encrypted_dns_usage"):
            score += 5

        mitre_count = sum(1 for m in c2_result.get("mitre_mappings", []) if m.get("detected"))
        score += min(10, mitre_count * 3)

        return min(100, score)

    def _generate_summary(self, c2_result: Dict) -> str:
        """Generate a human-readable C2 analysis summary."""
        parts = []
        dga = c2_result.get("dga_analysis", [])
        beacon = c2_result.get("beaconing_analysis", {}).get("overall", {})
        ioc = c2_result.get("ioc_matches", {})
        score = c2_result.get("overall_score", 0)

        if dga:
            parts.append(f"{len(dga)} potential DGA domains detected")
        if beacon.get("beaconing_detected"):
            parts.append(f"beaconing patterns found ({beacon.get('total_indicators', 0)} indicators)")
        if ioc.get("total_matches", 0) > 0:
            parts.append(f"{ioc['total_matches']} IOCs matched known malicious indicators")
        if c2_result.get("raw_socket_usage"):
            parts.append("raw socket usage detected")
        if c2_result.get("encrypted_dns_usage"):
            parts.append("encrypted DNS usage detected")
        if c2_result.get("suspicious_ports"):
            ports = [str(p["port"]) for p in c2_result["suspicious_ports"]]
            parts.append(f"suspicious ports: {', '.join(ports)}")

        if not parts:
            return f"No C2 indicators detected (score: {score}/100)"

        return f"C2 Score: {score}/100 — " + "; ".join(parts) + "."
