import logging
import os

logger = logging.getLogger(__name__)

try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("yara-python is not installed. YaraService will operate in degraded mode.")


class YaraService:
    def __init__(self, rules_dir: str):
        self.rules_dir = rules_dir
        self._rules = []
        self._compiled_rules = None
        self._available = YARA_AVAILABLE

    def load_rules(self):
        if not self._available:
            logger.warning("yara-python unavailable; cannot load rules.")
            return
        if not os.path.isdir(self.rules_dir):
            logger.warning("Rules directory does not exist: %s", self.rules_dir)
            return
        self._rules.clear()
        for entry in sorted(os.listdir(self.rules_dir)):
            if entry.lower().endswith(".yar") or entry.lower().endswith(".yara"):
                path = os.path.join(self.rules_dir, entry)
                if os.path.isfile(path):
                    try:
                        with open(path, "r", encoding="utf-8", errors="replace") as fh:
                            content = fh.read()
                        self._rules.append({"name": entry, "path": path, "content": content})
                        logger.debug("Loaded rule file: %s", entry)
                    except Exception:
                        logger.exception("Failed to read rule file: %s", entry)
        logger.info("Loaded %d rule file(s) from %s", len(self._rules), self.rules_dir)
        self.compile_rules()

    def compile_rules(self):
        if not self._available:
            logger.warning("yara-python unavailable; cannot compile rules.")
            return
        if not self._rules:
            self._compiled_rules = None
            logger.info("No rules to compile.")
            return
        namespaces = {}
        for r in self._rules:
            namespaces[r["name"]] = r["content"]
        try:
            self._compiled_rules = yara.compile(sources=namespaces)
            logger.info("Compiled %d rule(s) successfully.", len(self._rules))
        except yara.Error:
            logger.exception("YARA compilation failed; falling back to per-rule matching.")
            self._compiled_rules = None

    def scan_file(self, file_path: str) -> list[dict]:
        results = []
        if not self._available:
            logger.warning("yara-python unavailable; cannot scan file.")
            return results
        if not os.path.isfile(file_path):
            logger.warning("File not found: %s", file_path)
            return results
        try:
            if self._compiled_rules is not None:
                matches = self._compiled_rules.match(file_path)
                results = self._format_matches(matches)
            else:
                for r in self._rules:
                    try:
                        rule = yara.compile(source=r["content"])
                        matches = rule.match(file_path)
                        results.extend(self._format_matches(matches))
                    except Exception:
                        logger.warning("Rule %s failed on file %s", r["name"], file_path)
        except Exception:
            logger.exception("Error scanning file %s with YARA", file_path)
        return results

    def scan_strings(self, strings: list[str]) -> list[dict]:
        results = []
        if not self._available:
            return results
        if not strings:
            return results
        data = "\n".join(strings).encode("utf-8", errors="replace")
        try:
            if self._compiled_rules is not None:
                matches = self._compiled_rules.match(data=data)
                results = self._format_matches(matches)
            else:
                for r in self._rules:
                    try:
                        rule = yara.compile(source=r["content"])
                        matches = rule.match(data=data)
                        results.extend(self._format_matches(matches))
                    except Exception as e:
                        logger.warning("Rule %s failed to scan strings: %s", r.get("name", "?"), e)
        except Exception:
            logger.exception("Error scanning strings with YARA")
        return results

    def add_rule(self, rule_name: str, rule_text: str) -> None:
        if not self._available:
            logger.warning("yara-python unavailable; cannot add rule.")
            return
        try:
            yara.compile(source=rule_text)
        except yara.SyntaxError as e:
            raise ValueError(f"Invalid YARA rule syntax: {e}") from e
        self._rules = [r for r in self._rules if r["name"] != rule_name]
        self._rules.append({"name": rule_name, "path": None, "content": rule_text})
        self.compile_rules()
        logger.info("Added custom rule: %s", rule_name)

    def remove_rule(self, rule_name: str) -> None:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r["name"] != rule_name]
        if len(self._rules) < before:
            self.compile_rules()
            logger.info("Removed rule: %s", rule_name)
        else:
            logger.warning("Rule not found: %s", rule_name)

    def get_rule(self, rule_name: str) -> dict | None:
        for r in self._rules:
            if r["name"] == rule_name:
                return dict(r)
        return None

    def list_rules(self) -> list[dict]:
        return [dict(r) for r in self._rules]

    @staticmethod
    def _format_matches(matches) -> list[dict]:
        formatted = []
        for m in matches:
            strings = m.strings if hasattr(m, "strings") else []
            matched = []
            for s in strings:
                # Handle both tuple format (older yara-python) and YaraStringMatch objects (newer)
                if hasattr(s, "offset") and hasattr(s, "identifier"):
                    # YaraStringMatch object (newer yara-python)
                    data_val = s.matched_data if hasattr(s, "matched_data") else ""
                    if isinstance(data_val, bytes):
                        data_val = data_val.decode(errors="replace")
                    matched.append({
                        "offset": s.offset,
                        "identifier": s.identifier,
                        "data": str(data_val)[:200],
                    })
                elif isinstance(s, tuple) and len(s) >= 3:
                    # Legacy tuple format: (offset, identifier, data)
                    matched.append({
                        "offset": s[0],
                        "identifier": s[1],
                        "data": s[2].decode(errors="replace") if isinstance(s[2], bytes) else str(s[2]),
                    })
            formatted.append({
                "rule_name": m.rule if hasattr(m, "rule") else str(m),
                "description": m.meta.get("description", "") if hasattr(m, "meta") else "",
                "severity": m.meta.get("severity", "medium") if hasattr(m, "meta") else "medium",
                "matched_strings": matched,
                "tags": list(m.tags) if hasattr(m, "tags") else [],
            })
        return formatted
