import logging
import os
from utils.entropy import shannon_entropy as _shannon_entropy_shared

logger = logging.getLogger(__name__)

try:
    import numpy as np
    import onnxruntime as ort

    ONNX_AVAILABLE = True
except ImportError:
    ONNX_AVAILABLE = False
    logger.warning("onnxruntime/numpy not installed. MLService will use rule-based fallback.")

DANGEROUS_PERMS = {
    "READ_SMS", "RECEIVE_SMS", "SEND_SMS", "WRITE_SMS",
    "RECORD_AUDIO", "CAPTURE_AUDIO_OUTPUT",
    "CAMERA",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION", "ACCESS_BACKGROUND_LOCATION",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS",
    "READ_PHONE_STATE", "CALL_PHONE", "ADD_VOICEMAIL",
    "BIND_ACCESSIBILITY_SERVICE",
    "INSTALL_PACKAGES", "DELETE_PACKAGES",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
    "GET_TASKS", "REAL_GET_TASKS", "PACKAGE_USAGE_STATS",
}

SUSPICIOUS_APIS = {
    "Runtime.exec", "ProcessBuilder.start",
    "java.lang.reflect.Method.invoke", "Class.forName",
    "DexClassLoader", "PathClassLoader",
    "Cipher", "SecretKeySpec",
    "HttpURLConnection", "HttpsURLConnection", "OkHttpClient",
    "Socket", "ServerSocket", "DatagramSocket",
    "android.telephony.SmsManager.sendTextMessage",
    "MediaRecorder", "AudioRecord",
    "Camera.open",
    "LocationManager.requestLocationUpdates",
    "WebView.addJavascriptInterface",
    "WebView.loadUrl",
    "java.io.FileOutputStream", "java.io.FileInputStream",
}


class MLService:
    def __init__(self, model_path: str):
        self.model_path = model_path
        self.session = None
        self.available = False
        self._input_name = None
        self._output_name = None
        self.load_model()

    def load_model(self):
        if not ONNX_AVAILABLE:
            self.available = False
            logger.info("ONNX runtime unavailable; using rule-based fallback.")
            return
        if not os.path.isfile(self.model_path):
            logger.warning("Model file not found: %s; using rule-based fallback.", self.model_path)
            self.available = False
            return
        try:
            self.session = ort.InferenceSession(self.model_path)
            self._input_name = self.session.get_inputs()[0].name
            self._output_name = self.session.get_outputs()[0].name
            self.available = True
            logger.info("ONNX model loaded from %s", self.model_path)
        except Exception:
            logger.exception("Failed to load ONNX model from %s", self.model_path)
            self.available = False

    def extract_features(self, static_results: dict, c2_results: dict) -> list:
        if static_results is None:
            static_results = {}
        if c2_results is None:
            c2_results = {}

        permissions_data = static_results.get("permissions", [])
        if isinstance(permissions_data, dict):
            permissions = permissions_data.get("all_permissions", [])
        else:
            permissions = permissions_data or []
        dangerous_perm_count = sum(1 for p in permissions if p in DANGEROUS_PERMS)
        normal_perm_count = sum(1 for p in permissions if p.startswith("android.permission.") and p not in DANGEROUS_PERMS)
        custom_perm_count = sum(1 for p in permissions if not p.startswith("android.permission."))

        has_audio_rec = 1 if any("RECORD_AUDIO" in p or "CAPTURE_AUDIO" in p for p in permissions) else 0
        has_camera = 1 if any("CAMERA" in p for p in permissions) else 0
        has_sms = 1 if any("SMS" in p for p in permissions) else 0
        has_accessibility = 1 if any("ACCESSIBILITY" in p or "BIND_ACCESSIBILITY" in p for p in permissions) else 0

        urls = static_results.get("urls", [])
        ips = static_results.get("ips", [])
        url_count = len(urls) if urls else 0
        ip_count = len(ips) if ips else 0

        has_native_libs = 1 if static_results.get("has_native_libs", False) else 0

        strings_raw = static_results.get("strings", []) or []
        entropies = [_shannon_entropy_shared(s) for s in strings_raw if len(s) > 8]
        entropy_mean = float(np.mean(entropies)) if entropies else 0.0
        entropy_max = float(np.max(entropies)) if entropies else 0.0

        is_debuggable = 1 if static_results.get("debuggable", False) else 0
        is_self_signed = 1 if static_results.get("self_signed", False) else 0

        apis = static_results.get("api_calls", []) or []
        suspicious_api_count = sum(1 for a in apis if a in SUSPICIOUS_APIS)

        has_dga = 1 if c2_results.get("has_dga", False) or c2_results.get("dga_analysis") else 0
        beaconing_overall = c2_results.get("beaconing_analysis", {}).get("overall", {})
        has_beaconing = 1 if c2_results.get("has_beaconing", False) or beaconing_overall.get("beaconing_detected") else 0
        has_raw_socket = 1 if c2_results.get("has_raw_socket", False) or c2_results.get("raw_socket_usage", False) else 0
        has_dynamic_code = 1 if static_results.get("has_dynamic_code_loading", False) else 0
        has_webview = 1 if any("WebView" in a for a in apis) else 0

        min_sdk = static_results.get("min_sdk", 1) or 1
        target_sdk = static_results.get("target_sdk", 1) or 1

        high_entropy_count = sum(1 for e in entropies if e > 5.5)

        return [
            dangerous_perm_count,
            normal_perm_count,
            custom_perm_count,
            has_audio_rec,
            has_camera,
            has_sms,
            has_accessibility,
            url_count,
            ip_count,
            has_native_libs,
            entropy_mean,
            entropy_max,
            is_debuggable,
            is_self_signed,
            suspicious_api_count,
            has_dga,
            has_beaconing,
            has_raw_socket,
            has_dynamic_code,
            has_webview,
            min_sdk,
            target_sdk,
            high_entropy_count,
        ]

    def predict(self, features: list) -> dict:
        if self.available and self.session is not None:
            try:
                inp = np.array([features], dtype=np.float32)
                out = self.session.run([self._output_name], {self._input_name: inp})[0]
                probs = out[0] if out.ndim > 1 else out
                confidence = float(np.max(probs))
                class_id = int(np.argmax(probs))
                families = ["BankingTrojan", "RAT", "Ransomware", "Spyware", "Botnet", "Dropper", "Adware", "Riskware", "Benign"]
                family = families[class_id] if class_id < len(families) else "Unknown"
                return {"family": family, "confidence": round(confidence, 4), "model_used": "onnx"}
            except Exception:
                logger.exception("ONNX inference failed; falling back to rule-based.")
        return self._rule_based_predict(features)

    def _rule_based_predict(self, features: list) -> dict:
        (
            dangerous_perm_count,
            normal_perm_count,
            custom_perm_count,
            has_audio_rec,
            has_camera,
            has_sms,
            has_accessibility,
            url_count,
            ip_count,
            has_native_libs,
            entropy_mean,
            entropy_max,
            is_debuggable,
            is_self_signed,
            suspicious_api_count,
            has_dga,
            has_beaconing,
            has_raw_socket,
            has_dynamic_code,
            has_webview,
            min_sdk,
            target_sdk,
            high_entropy_count,
        ) = features

        score = 0.0
        signals = []

        if dangerous_perm_count >= 8:
            score += 30
            signals.append("high_dangerous_permissions")
        elif dangerous_perm_count >= 4:
            score += 15
            signals.append("moderate_dangerous_permissions")
        if has_audio_rec:
            score += 10
            signals.append("audio_recording")
        if has_camera:
            score += 10
            signals.append("camera_access")
        if has_sms:
            score += 10
            signals.append("sms_access")
        if has_accessibility:
            score += 15
            signals.append("accessibility_service")
        if url_count > 10:
            score += 8
            signals.append("many_urls")
        if ip_count > 5:
            score += 8
            signals.append("many_ips")
        if has_native_libs:
            score += 5
            signals.append("native_libraries")
        if entropy_max > 6.5:
            score += 10
            signals.append("high_entropy")
        if is_debuggable:
            score += 3
            signals.append("debuggable")
        if is_self_signed:
            score += 5
            signals.append("self_signed")
        if suspicious_api_count >= 10:
            score += 20
            signals.append("high_suspicious_apis")
        elif suspicious_api_count >= 5:
            score += 10
            signals.append("moderate_suspicious_apis")
        if has_dga:
            score += 15
            signals.append("dga_detected")
        if has_beaconing:
            score += 20
            signals.append("beaconing_detected")
        if has_raw_socket:
            score += 10
            signals.append("raw_socket")
        if has_dynamic_code:
            score += 12
            signals.append("dynamic_code_loading")
        if has_webview:
            score += 8
            signals.append("webview_detected")
        if high_entropy_count > 5:
            score += 10
            signals.append("many_high_entropy_strings")

        normalized_score = min(score / 100.0, 1.0)

        if score >= 70:
            family = "Ransomware"
        elif score >= 55:
            if has_sms and has_audio_rec:
                family = "Spyware"
            elif has_beaconing or has_dga:
                family = "BankingTrojan"
            else:
                family = "Ransomware"
        elif score >= 35:
            if has_sms:
                family = "Spyware"
            elif has_dynamic_code:
                family = "Dropper"
            elif ip_count > 3 or url_count > 5:
                family = "BankingTrojan"
            else:
                family = "Adware"
        elif score >= 15:
            family = "Adware"
        else:
            family = "Riskware" if dangerous_perm_count > 2 else "Benign"

        if family == "Benign" and score > 0:
            family = "Riskware"

        return {
            "family": family,
            "confidence": round(normalized_score, 4),
            "model_used": "rule_based",
        }

    @staticmethod
    def _shannon_entropy(data: str) -> float:
        """Delegate to shared entropy utility."""
        return _shannon_entropy_shared(data)

    def train(self, training_data_path: str) -> dict:
        logger.info("Training stub called with %s. Pipeline not yet implemented.", training_data_path)
        return {"status": "not_implemented", "message": "Training pipeline is not implemented in this version."}
