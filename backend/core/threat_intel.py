"""
Threat Intelligence & Risk Scoring Engine.
Combines static analysis and C2 detection results to produce
an overall risk score, category classification, and detailed forensic report.
"""
import logging
import os
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class RuleBasedScorer:
    """
    Implements the component scoring functions used in the final risk formula.
    Each method returns a score between 0 and 100.
    """

    @staticmethod
    def permission_score(static_results: Dict) -> Dict:
        """
        Calculate permission risk score.

        Factors:
        - Dangerous permission weight sum / max_possible * 100
        - Multiplier for custom permissions
        - Multiplier for high count of dangerous perms (>= 10: 1.2x, >= 5: 1.1x)
        - Bonus for debuggable manifest
        """
        perm_data = static_results.get("permissions", {})
        risk = perm_data.get("risk_score", {})
        categorized = perm_data.get("categorized", {})
        manifest = static_results.get("manifest", {})

        base = risk.get("score", 0)
        multiplier = 1.0

        custom_count = len(categorized.get("custom", []))
        if custom_count > 0:
            multiplier += min(0.3, custom_count * 0.05)

        dangerous_count = risk.get("dangerous_count", 0)
        if dangerous_count >= 10:
            multiplier += 0.20
        elif dangerous_count >= 5:
            multiplier += 0.10

        if manifest.get("debuggable"):
            multiplier += 0.15
        if manifest.get("allow_backup"):
            multiplier += 0.10
        if manifest.get("uses_cleartext_traffic"):
            multiplier += 0.10

        final = min(100, base * multiplier)
        return {
            "score": round(final, 2),
            "base_score": round(base, 2),
            "multiplier": round(multiplier, 2),
            "dangerous_count": dangerous_count,
            "custom_count": custom_count,
        }

    @staticmethod
    def ioc_score(static_results: Dict) -> Dict:
        """
        Calculate IOC (Indicator of Compromise) score from extracted strings.

        Factors:
        - URLs found (2 pts each, max 25)
        - IPs found (3 pts each, max 25)
        - Domains found (2 pts each, max 20)
        - High-entropy strings (3 pts each, max 20)
        - Base64 candidates (1 pt each, max 10)
        """
        strings = static_results.get("dex_strings", {})
        score = 0
        details = {}

        url_count = len(strings.get("urls", []))
        url_score = min(25, url_count * 2)
        score += url_score
        details["urls"] = {"count": url_count, "score": url_score}

        ip_count = len(strings.get("ips", []))
        ip_score = min(25, ip_count * 3)
        score += ip_score
        details["ips"] = {"count": ip_count, "score": ip_score}

        domain_count = len(strings.get("domains", []))
        domain_score = min(20, domain_count * 2)
        score += domain_score
        details["domains"] = {"count": domain_count, "score": domain_score}

        he_count = len(strings.get("high_entropy_strings", []))
        he_score = min(20, he_count * 3)
        score += he_score
        details["high_entropy"] = {"count": he_count, "score": he_score}

        b64_count = len(strings.get("base64_candidates", []))
        b64_score = min(10, b64_count)
        score += b64_score
        details["base64"] = {"count": b64_count, "score": b64_score}

        return {
            "score": round(min(100, score), 2),
            "details": details,
        }

    @staticmethod
    def c2_score(c2_results: Dict) -> Dict:
        """
        Calculate C2 threat score from C2 detector output.
        Simply maps the C2 detector's overall score.
        """
        overall = c2_results.get("overall_score", 0)
        details = {
            "dga_count": len(c2_results.get("dga_analysis", [])),
            "beaconing_detected": c2_results.get("beaconing_analysis", {}).get("overall", {}).get("beaconing_detected", False),
            "ioc_matches": c2_results.get("ioc_matches", {}).get("total_matches", 0),
            "suspicious_ports": len(c2_results.get("suspicious_ports", [])),
            "raw_sockets": c2_results.get("raw_socket_usage", False),
            "encrypted_dns": c2_results.get("encrypted_dns_usage", False),
            "mitre_count": sum(1 for m in c2_results.get("mitre_mappings", []) if m.get("detected")),
        }
        return {
            "score": round(overall, 2),
            "details": details,
        }

    @staticmethod
    def behavior_score(static_results: Dict) -> Dict:
        """
        Calculate behavior-based risk score.

        Checks for:
        - Dynamic code loading (DexClassLoader, PathClassLoader)
        - Accessibility service abuse
        - SMS intercept capabilities
        - Native code usage
        - Reflection API usage
        - Package querying
        """
        score = 0
        details = {}
        manifest = static_results.get("manifest", {})
        permissions = static_results.get("permissions", {})
        categorized = permissions.get("categorized", {})
        dangerous = set(categorized.get("dangerous", []))

        receivers = [r.get("name", "") for r in manifest.get("receivers", [])]
        activities = [a.get("name", "") for a in manifest.get("activities", [])]
        services = [s.get("name", "") for s in manifest.get("services", [])]

        sms_perms = {"android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"}
        if sms_perms.intersection(dangerous):
            sms_count = len(sms_perms.intersection(dangerous))
            sms_score = min(20, sms_count * 7)
            score += sms_score
            details["sms_capabilities"] = {"score": sms_score, "permissions": list(sms_perms.intersection(dangerous))}

        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in dangerous:
            score += 15
            details["accessibility_abuse"] = {"score": 15}

        dex_strings = static_results.get("dex_strings", {})
        he_strings = [s["value"] if isinstance(s, dict) and "value" in s else str(s) for s in dex_strings.get("high_entropy_strings", [])]
        combined = " ".join(he_strings)

        dynamic_loading = ["DexClassLoader", "PathClassLoader", "InMemoryDexClassLoader", "loadDex"]
        dl_found = [p for p in dynamic_loading if p in combined]
        if dl_found:
            dl_score = min(15, len(dl_found) * 5)
            score += dl_score
            details["dynamic_loading"] = {"score": dl_score, "classes": dl_found}

        reflection = ["Class.forName", "Method.invoke", "getDeclaredMethod", "setAccessible"]
        refl_found = [p for p in reflection if p in combined]
        if refl_found:
            refl_score = min(10, len(refl_found) * 3)
            score += refl_score
            details["reflection"] = {"score": refl_score, "patterns": refl_found}

        native_libs = static_results.get("native_libs", [])
        if native_libs:
            native_score = min(15, len(native_libs) * 3)
            score += native_score
            details["native_code"] = {"score": native_score, "library_count": len(native_libs)}

        if manifest.get("allow_backup"):
            score += 5
            details["allow_backup"] = {"score": 5}

        return {
            "score": round(min(100, score), 2),
            "details": details,
        }

    @staticmethod
    def anti_analysis_score(static_results: Dict) -> Dict:
        """
        Calculate anti-analysis evasion score.
        Maps directly from the anti-analysis detection results.
        """
        aa = static_results.get("anti_analysis", {}).get("overall", {})
        raw_score = aa.get("score", 0)
        return {
            "score": round(raw_score, 2),
            "details": {
                "total_indicators": aa.get("total_indicators", 0),
                "detected_any": aa.get("detected_any", False),
            },
        }

    @staticmethod
    def yara_score(yara_matches: list) -> Dict:
        """
        Calculate a risk score from YARA match results.

        Factors:
        - Each critical rule match: +20
        - Each high rule match: +15
        - Each medium rule match: +8
        - Each low rule match: +3
        - Bonus for multiple matches of same severity
        """
        score = 0
        details = {"matched_rules": [], "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}}

        for match in yara_matches:
            severity = match.get("severity", "medium").lower()
            rule_name = match.get("rule_name", "unknown")
            details["matched_rules"].append({"rule": rule_name, "severity": severity})
            details["counts"][severity] = details["counts"].get(severity, 0) + 1

            if severity == "critical":
                score += 20
            elif severity == "high":
                score += 15
            elif severity == "medium":
                score += 8
            elif severity == "low":
                score += 3

        # Bonus: multiple critical/high detections amplify the score
        if details["counts"]["critical"] >= 3:
            score += 10
        elif details["counts"]["high"] >= 3:
            score += 5

        return {
            "score": round(min(100, score), 2),
            "details": details,
        }


class MLClassifier:
    """
    Machine Learning classifier for APK malware family classification.
    Attempts to load an ONNX model; falls back gracefully if unavailable.
    Uses a rule-based fallback when no model is present.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path
        self.session = None
        self._loaded = False
        if model_path and os.path.isfile(model_path):
            self._load_model()
        else:
            logger.info("No ONNX model found at %s — will use rule-based fallback", model_path)

    def _load_model(self):
        """Try to load ONNX model."""
        try:
            import onnxruntime as ort
            self.session = ort.InferenceSession(self.model_path)
            self._loaded = True
            logger.info("ONNX model loaded successfully from %s", self.model_path)
        except ImportError:
            logger.warning("onnxruntime not installed — cannot load ONNX model")
        except Exception as e:
            logger.error("Failed to load ONNX model: %s", e)

    def classify(self, static_results: Dict, c2_results: Dict) -> Dict:
        """
        Classify the APK into a malware family.

        Returns dict with family label, confidence, and raw scores.
        """
        if self._loaded and self.session:
            return self._onnx_classify(static_results, c2_results)
        return self._rule_based_classify(static_results, c2_results)

    def _onnx_classify(self, static_results: Dict, c2_results: Dict) -> Dict:
        """Run ONNX inference. Falls back on error."""
        try:
            features = self._extract_features(static_results, c2_results)
            input_name = self.session.get_inputs()[0].name
            import numpy as np
            input_data = np.array([features], dtype=np.float32)
            outputs = self.session.run(None, {input_name: input_data})
            families = ["BankingTrojan", "RAT", "Ransomware", "Spyware", "Botnet", "Dropper", "Adware", "Riskware", "Benign"]
            scores = outputs[0][0] if len(outputs) > 0 else [0] * len(families)
            pred_idx = int(np.argmax(scores))
            confidence = float(np.max(scores))
            return {
                "family": families[pred_idx],
                "confidence": round(confidence, 4),
                "scores": {families[i]: round(float(scores[i]), 4) for i in range(len(families))},
                "model_used": True,
            }
        except Exception as e:
            logger.error("ONNX inference failed: %s — falling back to rule-based", e)
            return self._rule_based_classify(static_results, c2_results)

    def _rule_based_classify(self, static_results: Dict, c2_results: Dict) -> Dict:
        """
        Rule-based malware family classification as fallback.
        Uses indicator heuristics to determine likely family.
        """
        permissions = static_results.get("permissions", {})
        categorized = permissions.get("categorized", {})
        dangerous = set(categorized.get("dangerous", []))
        manifest = static_results.get("manifest", {})
        c2_score = c2_results.get("overall_score", 0)
        aa = static_results.get("anti_analysis", {}).get("overall", {})
        native_libs = static_results.get("native_libs", [])
        dex_strings = static_results.get("dex_strings", {})
        he_strings = dex_strings.get("high_entropy_strings", [])

        scores = {
            "BankingTrojan": 0,
            "RAT": 0,
            "Ransomware": 0,
            "Spyware": 0,
            "Botnet": 0,
            "Dropper": 0,
            "Adware": 0,
            "Riskware": 0,
            "Benign": 0,
        }

        sms_perms = {"android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"}
        loc_perms = {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}
        mic_cam = {"android.permission.RECORD_AUDIO", "android.permission.CAMERA"}

        if sms_perms.issubset(dangerous):
            scores["BankingTrojan"] += 20
            scores["Spyware"] += 15
        if loc_perms.issubset(dangerous) and mic_cam.issubset(dangerous):
            scores["Spyware"] += 20
            scores["RAT"] += 15
        if "android.permission.BIND_ACCESSIBILITY_SERVICE" in dangerous:
            scores["BankingTrojan"] += 20
            scores["RAT"] += 10
        if "android.permission.INSTALL_PACKAGES" in dangerous:
            scores["Dropper"] += 20

        if c2_score >= 60:
            scores["Botnet"] += 20
            scores["RAT"] += 15
        elif c2_score >= 30:
            scores["RAT"] += 10
            scores["Botnet"] += 10

        if aa.get("detected_any"):
            scores["BankingTrojan"] += 10
            scores["RAT"] += 10

        if len(native_libs) > 3:
            scores["RAT"] += 5
            scores["BankingTrojan"] += 5

        if len(he_strings) > 20:
            scores["Ransomware"] += 10
            scores["Spyware"] += 5

        receiver_names = [r.get("name", "").lower() for r in manifest.get("receivers", [])]
        boot_receivers = [r for r in receiver_names if "boot" in r]
        if boot_receivers:
            scores["Botnet"] += 10
            scores["Spyware"] += 5

        if not any(v > 5 for v in scores.values()):
            scores["Benign"] += 50
        else:
            scores["Benign"] = max(0, scores["Benign"] - 20)

        total = sum(scores.values()) or 1
        confidence_scores = {k: round(v / total, 4) for k, v in scores.items()}
        best_family = max(confidence_scores, key=confidence_scores.get)
        best_confidence = confidence_scores[best_family]

        return {
            "family": best_family,
            "confidence": best_confidence,
            "scores": confidence_scores,
            "model_used": False,
        }

    def _extract_features(self, static_results: Dict, c2_results: Dict) -> List[float]:
        """Extract numerical feature vector for model inference."""
        permissions = static_results.get("permissions", {})
        risk = permissions.get("risk_score", {})
        dex_strings = static_results.get("dex_strings", {})
        manifest = static_results.get("manifest", {})

        features = [
            float(risk.get("score", 0)),
            float(risk.get("dangerous_count", 0)),
            float(len(dex_strings.get("urls", []))),
            float(len(dex_strings.get("ips", []))),
            float(len(dex_strings.get("domains", []))),
            float(len(dex_strings.get("high_entropy_strings", []))),
            float(len(static_results.get("native_libs", []))),
            float(static_results.get("anti_analysis", {}).get("overall", {}).get("score", 0)),
            float(c2_results.get("overall_score", 0)),
            float(len(c2_results.get("dga_analysis", []))),
            float(1 if c2_results.get("beaconing_analysis", {}).get("overall", {}).get("beaconing_detected") else 0),
            float(1 if manifest.get("debuggable") else 0),
            float(1 if manifest.get("allow_backup") else 0),
            float(len(manifest.get("receivers", []))),
            float(len(manifest.get("services", []))),
        ]
        return features


class ThreatEngine:
    """
    Main threat intelligence engine.
    Combines static analysis and C2 detection results using the weighted formula
    to produce a final risk assessment.
    """

    SCORE_FORMULA = {
        "permission_weight": 0.30,
        "ioc_weight": 0.20,
        "c2_weight": 0.25,
        "behavior_weight": 0.15,
        "anti_analysis_weight": 0.10,
    }

    CATEGORY_BOUNDARIES = [
        ("Safe", 0, 15),
        ("Low Risk", 16, 35),
        ("Medium Risk", 36, 55),
        ("High Risk", 56, 75),
        ("Critical", 76, 100),
    ]

    MALWARE_FAMILY_BOOSTS = {
        "BankingTrojan": 10,
        "RAT": 10,
        "Ransomware": 10,
        "Spyware": 8,
        "Botnet": 8,
        "Dropper": 5,
        "Adware": 3,
    }

    def __init__(self, ml_model_path: Optional[str] = None):
        self.scorer = RuleBasedScorer()
        self.ml_classifier = MLClassifier(ml_model_path)

    def calculate(
        self,
        static_results: dict,
        c2_results: dict,
        ml_classification: Optional[dict] = None,
        yara_matches: Optional[list] = None,
    ) -> Dict:
        """
        Calculate the comprehensive threat risk score.

        Formula:
            FINAL_SCORE = min(100, max(0,
                (PERMISSION_SCORE * 0.30) +
                (IOC_SCORE * 0.20) +
                (C2_SCORE * 0.25) +
                (BEHAVIOR_SCORE * 0.15) +
                (ANTI_ANALYSIS_SCORE * 0.10)
                + YARA_BOOST
                + FAMILY_BOOST
            ))

        Args:
            static_results: Output from StaticAnalyzer.analyze()
            c2_results: Output from C2Detector.analyze()
            ml_classification: Optional pre-computed ML classification.
                              If None, runs ML classifier internally.
            yara_matches: Optional list of YARA match dicts from YaraService.

        Returns:
            Dict with overall_score, category, component breakdown, and explanation.
        """
        try:
            perm = self.scorer.permission_score(static_results)
            ioc = self.scorer.ioc_score(static_results)
            c2 = self.scorer.c2_score(c2_results)
            behavior = self.scorer.behavior_score(static_results)
            anti = self.scorer.anti_analysis_score(static_results)
            yara = self.scorer.yara_score(yara_matches or [])

            if ml_classification is None:
                ml_classification = self.ml_classifier.classify(static_results, c2_results)

            family_boost = self._calculate_family_boost(ml_classification)

            raw_score = (
                perm["score"] * self.SCORE_FORMULA["permission_weight"]
                + ioc["score"] * self.SCORE_FORMULA["ioc_weight"]
                + c2["score"] * self.SCORE_FORMULA["c2_weight"]
                + behavior["score"] * self.SCORE_FORMULA["behavior_weight"]
                + anti["score"] * self.SCORE_FORMULA["anti_analysis_weight"]
            )

            # YARA boost is additive (like family_boost), not weighted
            yara_boost = min(15, yara["score"] * 0.15)

            final_score = min(100, max(0, raw_score + yara_boost + family_boost))
            final_score = round(final_score, 2)

            category = self._classify(final_score)
            explanation = self._generate_explanation(
                final_score, category, perm, ioc, c2, behavior, anti,
                family_boost, ml_classification, static_results,
            )

            return {
                "overall_score": final_score,
                "category": category,
                "yara_boost": round(yara_boost, 2),
                "family_boost": family_boost,
                "family_classification": ml_classification,
                "components": {
                    "permission_score": perm,
                    "ioc_score": ioc,
                    "c2_score": c2,
                    "behavior_score": behavior,
                    "anti_analysis_score": anti,
                    "yara_score": yara,
                },
                "explanation": explanation,
            }

        except Exception as e:
            logger.exception("Threat intelligence calculation failed")
            return {
                "overall_score": 0,
                "category": "Error",
                "family_boost": 0,
                "family_classification": {"family": "Unknown", "confidence": 0},
                "components": {},
                "explanation": f"Error during threat calculation: {str(e)}",
            }

    def _calculate_family_boost(self, ml_classification: Dict) -> float:
        """Calculate family boost based on ML classification."""
        family = ml_classification.get("family", "")
        confidence = ml_classification.get("confidence", 0)
        if isinstance(confidence, (int, float)) and confidence > 0.7:
            return self.MALWARE_FAMILY_BOOSTS.get(family, 0)
        return 0.0

    def _classify(self, score: float) -> str:
        """Classify score into a threat category."""
        for name, lower, upper in self.CATEGORY_BOUNDARIES:
            if lower <= score <= upper:
                return name
        return "Critical"

    def _generate_explanation(
        self,
        final_score: float,
        category: str,
        perm: Dict,
        ioc: Dict,
        c2: Dict,
        behavior: Dict,
        anti: Dict,
        family_boost: float,
        ml_classification: Dict,
        static_results: Dict,
    ) -> str:
        """Generate a detailed human-readable explanation of the risk assessment."""
        lines = []
        lines.append(f"Overall Risk Score: {final_score}/100 — Category: {category}")
        lines.append("")

        lines.append("Component Breakdown:")
        lines.append(f"  Permission Risk: {perm['score']}/100 (base: {perm['base_score']}, multiplier: {perm['multiplier']}x, dangerous: {perm['dangerous_count']}, custom: {perm['custom_count']})")
        lines.append(f"  IOC Risk: {ioc['score']}/100 (URLs: {ioc['details']['urls']['count']}, IPs: {ioc['details']['ips']['count']}, Domains: {ioc['details']['domains']['count']}, High-Entropy: {ioc['details']['high_entropy']['count']})")
        lines.append(f"  C2 Risk: {c2['score']}/100 (DGA domains: {c2['details']['dga_count']}, Beaconing: {c2['details']['beaconing_detected']}, IOC matches: {c2['details']['ioc_matches']}, Suspicious ports: {c2['details']['suspicious_ports']})")
        lines.append(f"  Behavior Risk: {behavior['score']}/100")
        lines.append(f"  Anti-Analysis Risk: {anti['score']}/100 (indicators: {anti['details']['total_indicators']})")
        lines.append("")

        if family_boost > 0:
            lines.append(f"Malware Family Boost: +{family_boost} (classified as {ml_classification['family']} with {ml_classification['confidence']:.1%} confidence)")
        else:
            lines.append(f"Malware Classification: {ml_classification['family']} (confidence: {ml_classification.get('confidence', 0):.1%})")

        lines.append("")

        perm_detail = static_results.get("permissions", {})
        dangerous_combos = perm_detail.get("dangerous_combinations", [])
        if dangerous_combos:
            lines.append("Dangerous Permission Combinations: " + ", ".join(dangerous_combos))

        manifest = static_results.get("manifest", {})
        flags = []
        if manifest.get("debuggable"):
            flags.append("debuggable")
        if manifest.get("allow_backup"):
            flags.append("allowBackup enabled")
        if manifest.get("uses_cleartext_traffic"):
            flags.append("cleartext traffic allowed")
        if flags:
            lines.append("Manifest Risk Flags: " + ", ".join(flags))

        return "\n".join(lines)

    def export_report(self, static_results: dict, c2_results: dict, threat_results: dict) -> Dict:
        """
        Generate a complete forensic evidence report.

        Returns a dict with structured report data suitable for PDF/JSON export.
        """
        return {
            "report_metadata": {
                "generated_by": "APK Threat Analysis Platform v1.0",
                "type": "forensic_evidence_report",
            },
            "file_info": static_results.get("file_info", {}),
            "manifest": static_results.get("manifest", {}),
            "risk_assessment": {
                "overall_score": threat_results.get("overall_score", 0),
                "category": threat_results.get("category", "Unknown"),
                "components": threat_results.get("components", {}),
                "family_classification": threat_results.get("family_classification", {}),
            },
            "permissions": {
                "dangerous": static_results.get("permissions", {}).get("categorized", {}).get("dangerous", []),
                "dangerous_combinations": static_results.get("permissions", {}).get("dangerous_combinations", []),
            },
            "indicators": {
                "urls": static_results.get("dex_strings", {}).get("urls", []),
                "ips": static_results.get("dex_strings", {}).get("ips", []),
                "domains": static_results.get("dex_strings", {}).get("domains", []),
                "emails": static_results.get("dex_strings", {}).get("emails", []),
                "high_entropy_strings": static_results.get("dex_strings", {}).get("high_entropy_strings", [])[:20],
            },
            "c2_analysis": {
                "dga_domains": c2_results.get("dga_analysis", []),
                "beaconing": c2_results.get("beaconing_analysis", {}),
                "ioc_matches": c2_results.get("ioc_matches", {}),
                "suspicious_ports": c2_results.get("suspicious_ports", []),
                "raw_sockets": c2_results.get("raw_socket_usage", False),
                "encrypted_dns": c2_results.get("encrypted_dns_usage", False),
                "mitre_mappings": c2_results.get("mitre_mappings", []),
            },
            "anti_analysis": static_results.get("anti_analysis", {}),
            "native_libraries": static_results.get("native_libs", []),
            "explanation": threat_results.get("explanation", ""),
        }
