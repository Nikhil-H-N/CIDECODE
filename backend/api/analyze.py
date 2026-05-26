import asyncio
import os
from datetime import datetime
from typing import Optional

from database.memory_db import ObjectId
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, status
from loguru import logger
from pydantic import BaseModel

from config import settings
from core import C2Detector, StaticAnalyzer, ThreatEngine
from database.connection import get_database
from models import AnalysisResult, C2Detection, MLClassification, StaticAnalysis, ThreatScore, ThreatScoreComponents, YaraMatch
from services import MLService, YaraService
from services.decompiler_service import DecompilerService

router = APIRouter(tags=["Analysis"])


class AnalyzeRequest(BaseModel):
    apk_id: str


# --- Singleton services (created once, reused for all analyses) ---
_static_analyzer: Optional[StaticAnalyzer] = None
_c2_detector: Optional[C2Detector] = None
_yara_service: Optional[YaraService] = None
_threat_engine: Optional[ThreatEngine] = None
_ml_service: Optional[MLService] = None
_decompiler_service: Optional[DecompilerService] = None
_ioc_db: Optional[dict] = None


def _get_static_analyzer() -> StaticAnalyzer:
    global _static_analyzer
    if _static_analyzer is None:
        _static_analyzer = StaticAnalyzer()
    return _static_analyzer


def _get_c2_detector() -> C2Detector:
    global _c2_detector
    if _c2_detector is None:
        _c2_detector = C2Detector()
    return _c2_detector


def _get_yara_service() -> YaraService:
    global _yara_service
    if _yara_service is None:
        _yara_service = YaraService(settings.YARA_RULES_DIR)
        _yara_service.load_rules()
    return _yara_service


def _get_threat_engine() -> ThreatEngine:
    global _threat_engine
    if _threat_engine is None:
        _threat_engine = ThreatEngine(settings.ML_MODEL_PATH)
    return _threat_engine


def _get_ml_service() -> MLService:
    global _ml_service
    if _ml_service is None:
        _ml_service = MLService(settings.ML_MODEL_PATH)
    return _ml_service


def _get_decompiler_service() -> DecompilerService:
    global _decompiler_service
    if _decompiler_service is None:
        _decompiler_service = DecompilerService()
    return _decompiler_service


def _load_ioc_database() -> dict:
    """Load IOC data from seed files. Cached after first call."""
    global _ioc_db
    if _ioc_db is not None:
        return _ioc_db

    ioc_db = {"urls": [], "domains": [], "ips": [], "hashes": []}
    ioc_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), settings.IOC_DIR)

    file_map = {
        "malicious_ips.txt": "ips",
        "malicious_domains.txt": "domains",
        "malware_hashes.txt": "hashes",
    }

    for filename, key in file_map.items():
        filepath = os.path.join(ioc_dir, filename)
        if not os.path.isfile(filepath):
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                value = line.split("#")[0].strip()
                if value:
                    ioc_db[key].append(value)

    # Also load IOCs from the in-memory database (seeded on startup)
    _ioc_db = ioc_db
    logger.info(f"Loaded IOC database: {len(ioc_db['ips'])} IPs, {len(ioc_db['domains'])} domains, {len(ioc_db['hashes'])} hashes")
    return ioc_db


async def _load_ioc_database_from_db(db) -> dict:
    """Load IOC data from the in-memory database and merge with file-based IOCs."""
    base_ioc_db = _load_ioc_database()
    ioc_db = {key: list(values) for key, values in base_ioc_db.items()}
    seen = {key: set(values) for key, values in ioc_db.items()}

    # Merge with DB-seeded IOCs
    db_iocs = await db.iocs.find({"status": "active"}).to_list(length=10000)
    for ioc in db_iocs:
        ioc_type = ioc.get("type", "")
        value = ioc.get("value", "")
        if not value:
            continue
        if ioc_type == "ip" and value not in seen["ips"]:
            ioc_db["ips"].append(value)
            seen["ips"].add(value)
        elif ioc_type == "domain" and value not in seen["domains"]:
            ioc_db["domains"].append(value)
            seen["domains"].add(value)
        elif ioc_type == "hash" and value not in seen["hashes"]:
            ioc_db["hashes"].append(value)
            seen["hashes"].add(value)

    return ioc_db


async def run_analysis_pipeline(apk_id: str):
    db = await get_database()
    started_at = datetime.utcnow()

    try:
        apk_doc = await db.apks.find_one({"_id": ObjectId(apk_id)})
        if not apk_doc:
            logger.error(f"APK not found for analysis: {apk_id}")
            return

        apk_path = apk_doc.get("stored_path", "")
        if not apk_path:
            logger.error(f"No stored_path for APK: {apk_id}")
            return

        await db.apks.update_one({"_id": ObjectId(apk_id)}, {"$set": {"status": "analyzing"}})

        initial_doc = AnalysisResult(
            apk_id=apk_id,
            status="running",
            started_at=started_at,
        )
        await db.analysis_results.insert_one(initial_doc.to_dict())

        loop = asyncio.get_running_loop()
        timeout = settings.ANALYSIS_TIMEOUT

        async def run_analysis_steps():
            # --- Step 1: Static Analysis ---
            logger.info(f"[{apk_id}] Starting static analysis...")
            static_analyzer = _get_static_analyzer()
            static_results = await loop.run_in_executor(None, static_analyzer.analyze, apk_path)

            # --- Step 2: Optional JADX decompilation ---
            decompiled_strings = []
            decompiler = _get_decompiler_service()
            if await decompiler.is_jadx_available():
                logger.info(f"[{apk_id}] Decompiling with JADX...")
                jadx_output = await decompiler.decompile_with_jadx(apk_path)
                if jadx_output:
                    # Extract strings from decompiled Java source files
                    for root, dirs, files in os.walk(jadx_output):
                        for fname in files:
                            if fname.endswith(".java"):
                                try:
                                    fpath = os.path.join(root, fname)
                                    with open(fpath, "r", encoding="utf-8", errors="replace") as jf:
                                        for line in jf:
                                            line = line.strip()
                                            if len(line) > 8 and line.isprintable():
                                                decompiled_strings.append(line)
                                except Exception:
                                    pass
                    logger.info(f"[{apk_id}] Extracted {len(decompiled_strings)} strings from JADX output")
            else:
                logger.info(f"[{apk_id}] JADX not available, skipping decompilation")

            # --- Step 3: C2 Detection ---
            logger.info(f"[{apk_id}] Starting C2 detection...")
            c2_detector = _get_c2_detector()

            # Load IOC database (from files + in-memory DB)
            ioc_db = await _load_ioc_database_from_db(db)
            c2_detector.set_ioc_database(ioc_db)

            # Build the input for C2 detector: static results + decompiled strings
            c2_input = dict(static_results)
            if decompiled_strings:
                existing_strings = c2_input.get("dex_strings", {}).get("raw_strings", [])
                c2_input.setdefault("dex_strings", {})["raw_strings"] = existing_strings + decompiled_strings

            # Pass ALL strings to C2 detector (not just high-entropy) for beaconing/ports/etc.
            all_strings = []
            dex_strings = static_results.get("dex_strings", {})
            for key in ("raw_strings", "high_entropy_strings"):
                for s in dex_strings.get(key, []):
                    if isinstance(s, dict):
                        all_strings.append(s.get("value", ""))
                    else:
                        all_strings.append(str(s))
            if decompiled_strings:
                all_strings.extend(decompiled_strings)
            c2_input["_all_strings_for_beaconing"] = all_strings

            c2_results = await loop.run_in_executor(None, c2_detector.analyze, c2_input)

            # --- Step 4: ML Classification ---
            logger.info(f"[{apk_id}] Running ML classification...")
            ml_service = _get_ml_service()
            flat = {
                "permissions": static_results.get("permissions", {}).get("all_permissions", []),
                "urls": static_results.get("dex_strings", {}).get("urls", []),
                "ips": static_results.get("dex_strings", {}).get("ips", []),
                "has_native_libs": len(static_results.get("native_libs", [])) > 0,
                "strings": [
                    s["value"] if isinstance(s, dict) else str(s)
                    for s in static_results.get("dex_strings", {}).get("high_entropy_strings", [])
                ],
                "debuggable": static_results.get("manifest", {}).get("debuggable", False),
                "self_signed": bool(static_results.get("certificate", {}).get("is_self_signed", False)),
                "api_calls": [],
                "has_dynamic_code_loading": bool(
                    static_results.get("anti_analysis", {}).get("obfuscation", {}).get("detected", False)
                ),
                "min_sdk": static_results.get("manifest", {}).get("min_sdk", 1) or 1,
                "target_sdk": static_results.get("manifest", {}).get("target_sdk", 1) or 1,
            }
            features = ml_service.extract_features(flat, c2_results)
            ml_classification = ml_service.predict(features)

            # --- Step 5: YARA Scanning (file + all strings) ---
            logger.info(f"[{apk_id}] Running YARA scan...")
            yara_service = _get_yara_service()

            # Scan the actual APK binary (catches binary patterns)
            yara_file_matches = []
            try:
                yara_file_matches = yara_service.scan_file(apk_path)
            except Exception as e:
                logger.warning(f"[{apk_id}] YARA file scan failed: {e}")

            # Scan ALL extracted strings (not just high-entropy)
            yara_string_matches = yara_service.scan_strings(all_strings)

            # Merge and dedup by rule name
            seen_rules = set()
            yara_matches_raw = []
            for match in yara_file_matches + yara_string_matches:
                rule_name = match.get("rule_name", "")
                if rule_name not in seen_rules:
                    seen_rules.add(rule_name)
                    yara_matches_raw.append(match)

            logger.info(f"[{apk_id}] YARA: {len(yara_file_matches)} file matches, {len(yara_string_matches)} string matches, {len(yara_matches_raw)} unique")

            # --- Step 6: Threat Scoring ---
            logger.info(f"[{apk_id}] Calculating threat score...")
            threat_engine = _get_threat_engine()
            threat_result = await loop.run_in_executor(
                None,
                lambda: threat_engine.calculate(static_results, c2_results, ml_classification, yara_matches_raw),
            )

            # --- Build output models ---
            dex = static_results.get("dex_strings", {})
            manifest = static_results.get("manifest", {})
            cert = static_results.get("certificate", {})
            perm_data = static_results.get("permissions", {})

            perm_list = []
            for cat in ("dangerous", "normal", "signature", "custom"):
                for p in perm_data.get("categorized", {}).get(cat, []):
                    perm_list.append({"name": p, "category": cat})

            sa = StaticAnalysis(
                permissions=perm_list,
                manifest=manifest,
                strings=all_strings[:500],  # cap to avoid huge payloads
                urls=dex.get("urls", []),
                ips=dex.get("ips", []),
                domains=dex.get("domains", []),
                certificate=cert,
                entropy=float(dex.get("high_entropy_strings", [{}])[0].get("entropy", 0)) if dex.get("high_entropy_strings") else 0.0,
                native_libs=[lib.get("name", "") for lib in static_results.get("native_libs", [])],
                anti_analysis=[
                    f"{k}: {v.get('count', 0)} indicators"
                    for k, v in static_results.get("anti_analysis", {}).items()
                    if isinstance(v, dict) and v.get("detected")
                ],
            )

            beaconing_analysis = c2_results.get("beaconing_analysis", {})
            beaconing_data = []
            for key, val in beaconing_analysis.items():
                if isinstance(val, dict) and key not in ("overall", "suspicious_intervals_ms"):
                    beaconing_data.append({"category": key, "detected": val.get("detected", False), "patterns": val.get("patterns_found", [])})
            intervals = beaconing_analysis.get("suspicious_intervals_ms", [])
            if intervals:
                beaconing_data.append({"category": "suspicious_intervals", "detected": True, "patterns": [str(i) + "ms" for i in intervals]})

            c2d = C2Detection(
                total_destinations=len(dex.get("urls", [])) + len(dex.get("ips", [])) + len(dex.get("domains", [])),
                suspicious_destinations=len(c2_results.get("dga_analysis", [])),
                ioc_matches=[m.get("ioc", "") for m in c2_results.get("ioc_matches", {}).get("url_matches", [])]
                + [m.get("ioc", "") for m in c2_results.get("ioc_matches", {}).get("domain_matches", [])]
                + [m.get("ioc", "") for m in c2_results.get("ioc_matches", {}).get("ip_matches", [])],
                beaconing=beaconing_data,
                dga_domains=[d.get("domain", "") for d in c2_results.get("dga_analysis", [])],
                geolocation=c2_results.get("geolocation", []),
                mitre_techniques=[m.get("technique", "") for m in c2_results.get("mitre_mappings", []) if m.get("detected")],
            )

            comp = threat_result.get("components", {})
            mlc = threat_result.get("family_classification", {})
            tsc = ThreatScoreComponents(
                permissions_score=comp.get("permission_score", {}).get("score", 0),
                static_analysis_score=comp.get("ioc_score", {}).get("score", 0),
                c2_score=comp.get("c2_score", {}).get("score", 0),
                yara_score=comp.get("yara_score", {}).get("score", 0),
                ml_score=mlc.get("confidence", 0) * 100 if isinstance(mlc.get("confidence"), (int, float)) else 0.0,
            )
            ts = ThreatScore(
                overall_score=threat_result.get("overall_score", 0),
                category=threat_result.get("category", "Unknown"),
                components=tsc,
                ml_classification=MLClassification(
                    model_used=str(mlc.get("model_used", "rule_based")),
                    prediction=mlc.get("family", "Unknown"),
                    confidence=mlc.get("confidence", 0),
                    probabilities=mlc.get("scores", {}),
                ),
            )

            yara_matches_models = []
            for ym in yara_matches_raw:
                yara_matches_models.append(YaraMatch(
                    rule_name=ym.get("rule_name", ""),
                    description=ym.get("description", ""),
                    severity=ym.get("severity", "medium"),
                    matched_strings=[ms.get("data", "") if isinstance(ms, dict) else str(ms) for ms in ym.get("matched_strings", [])],
                    tags=ym.get("tags", []),
                ))

            completed_at = datetime.utcnow()
            analysis = AnalysisResult(
                apk_id=apk_id,
                status="completed",
                started_at=started_at,
                completed_at=completed_at,
                static_analysis=sa,
                c2_detection=c2d,
                threat_score=ts,
                yara_matches=yara_matches_models,
            )

            await db.analysis_results.replace_one(
                {"apk_id": apk_id},
                analysis.to_dict(),
                upsert=True,
            )
            package_name = static_results.get("manifest", {}).get("package", "")
            apk_update = {"status": "completed", "completed_at": completed_at.isoformat()}
            if package_name:
                apk_update["package_name"] = package_name
            await db.apks.update_one(
                {"_id": ObjectId(apk_id)},
                {"$set": apk_update},
            )

            logger.info(f"[{apk_id}] Analysis completed. Score: {ts.overall_score} ({ts.category})")

        # Proper timeout with task cancellation
        task = asyncio.create_task(run_analysis_steps())
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except asyncio.TimeoutError:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            logger.error(f"[{apk_id}] Analysis timed out after {settings.ANALYSIS_TIMEOUT}s")
            try:
                await db.analysis_results.update_one(
                    {"apk_id": apk_id},
                    {"$set": {"status": "failed", "error_message": f"Analysis timed out after {settings.ANALYSIS_TIMEOUT} seconds", "completed_at": datetime.utcnow()}},
                    upsert=True,
                )
                await db.apks.update_one(
                    {"_id": ObjectId(apk_id)},
                    {"$set": {"status": "failed"}},
                )
            except Exception as db_err:
                logger.error(f"[{apk_id}] Failed to update timeout status: {db_err}")

    except Exception as e:
        logger.exception(f"[{apk_id}] Analysis failed: {e}")
        try:
            await db.analysis_results.update_one(
                {"apk_id": apk_id},
                {"$set": {"status": "failed", "error_message": str(e), "completed_at": datetime.utcnow()}},
                upsert=True,
            )
            await db.apks.update_one(
                {"_id": ObjectId(apk_id)},
                {"$set": {"status": "failed"}},
            )
        except Exception as db_err:
            logger.error(f"[{apk_id}] Failed to update error status: {db_err}")


@router.post("/analyze")
async def start_analysis(
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    db=Depends(get_database),
):
    try:
        apk = await db.apks.find_one({"_id": ObjectId(req.apk_id)})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid APK ID format")

    if not apk:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="APK not found")

    if apk.get("status") in ("analyzing", "running"):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Analysis already in progress")

    background_tasks.add_task(run_analysis_pipeline, req.apk_id)

    return {
        "id": req.apk_id,
        "status": "started",
        "message": "Analysis pipeline started",
    }


@router.get("/analyze/{apk_id}")
async def get_analysis(apk_id: str, db=Depends(get_database)):
    try:
        doc = await db.analysis_results.find_one({"apk_id": apk_id})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ID format")

    if not doc:
        apk = await db.apks.find_one({"_id": ObjectId(apk_id)})
        if apk:
            return {"apk_id": apk_id, "status": apk.get("status", "pending"), "detail": "Analysis not yet completed"}
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    doc["_id"] = str(doc["_id"])

    if doc.get("threat_score") and isinstance(doc["threat_score"], dict):
        ts = doc["threat_score"]
        return {
            "id": doc["_id"],
            "apk_id": doc["apk_id"],
            "status": doc["status"],
            "threat_score": {
                "overall_score": ts.get("overall_score", 0),
                "category": ts.get("category", "Unknown"),
            },
            "started_at": doc.get("started_at"),
            "completed_at": doc.get("completed_at"),
        }

    return {
        "id": doc["_id"],
        "apk_id": doc["apk_id"],
        "status": doc["status"],
    }


@router.get("/analyze/{apk_id}/results")
async def get_analysis_results(apk_id: str, db=Depends(get_database)):
    try:
        doc = await db.analysis_results.find_one({"apk_id": apk_id})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ID format")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    doc["_id"] = str(doc["_id"])

    for key in ("started_at", "completed_at"):
        if isinstance(doc.get(key), datetime):
            doc[key] = doc[key].isoformat()

    return doc


@router.get("/analyze/{apk_id}/summary")
async def get_analysis_summary(apk_id: str, db=Depends(get_database)):
    try:
        doc = await db.analysis_results.find_one({"apk_id": apk_id})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ID format")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Analysis not found")

    ts = doc.get("threat_score", {})
    sa = doc.get("static_analysis", {})
    c2 = doc.get("c2_detection", {})
    mlc = ts.get("ml_classification", {})

    return {
        "apk_id": doc["apk_id"],
        "status": doc.get("status"),
        "threat_score": {
            "overall_score": ts.get("overall_score", 0),
            "category": ts.get("category", "Unknown"),
        },
        "ml_classification": {
            "family": mlc.get("prediction", "Unknown"),
            "confidence": mlc.get("confidence", 0),
        },
        "key_findings": {
            "dangerous_permissions": len(sa.get("permissions", [])),
            "urls_found": len(sa.get("urls", [])),
            "ips_found": len(sa.get("ips", [])),
            "domains_found": len(sa.get("domains", [])),
            "dga_domains": len(c2.get("dga_domains", [])),
            "ioc_matches": len(c2.get("ioc_matches", [])),
            "yara_matches": len(doc.get("yara_matches", [])),
            "mitre_techniques": len(c2.get("mitre_techniques", [])),
        },
    }
