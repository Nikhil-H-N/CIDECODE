from typing import Optional

from database.memory_db import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger

from database.connection import get_database

router = APIRouter(tags=["Search"])


@router.get("/search")
async def search(
    q: str = Query(..., min_length=1, description="Search term"),
    type: Optional[str] = Query(None, description="Filter by type: domain, ip, hash, package"),
    page: int = Query(1, ge=1, description="Page number"),
    limit: int = Query(20, ge=1, le=100, description="Results per page"),
    db=Depends(get_database),
):
    skip = (page - 1) * limit
    regex_pattern = {"$regex": q, "$options": "i"}

    if type == "hash":
        apks = await db.apks.find({
            "$or": [
                {"sha256": regex_pattern},
                {"sha1": regex_pattern},
                {"md5": regex_pattern},
            ]
        }).to_list(length=limit)

        results = []
        for apk in apks:
            apk["_id"] = str(apk["_id"])
            analysis = await db.analysis_results.find_one({"apk_id": apk["_id"]})
            if analysis:
                analysis["_id"] = str(analysis["_id"])
                results.append(analysis)
            else:
                results.append({"apk_id": apk["_id"], "status": "pending", "apk": apk})

        return {
            "total": len(results),
            "page": page,
            "limit": limit,
            "results": results,
        }

    if type == "package":
        apks = await db.apks.find({
            "package_name": regex_pattern,
        }).to_list(length=limit)

        results = []
        for apk in apks:
            apk["_id"] = str(apk["_id"])
            analysis = await db.analysis_results.find_one({"apk_id": apk["_id"]})
            if analysis:
                analysis["_id"] = str(analysis["_id"])
                results.append(analysis)
            else:
                results.append({"apk_id": apk["_id"], "status": "pending", "apk": apk})

        return {
            "total": len(results),
            "page": page,
            "limit": limit,
            "results": results,
        }

    match_conditions = []

    if type == "domain":
        match_conditions.append({"static_analysis.domains": regex_pattern})
    elif type == "ip":
        match_conditions.append({"static_analysis.ips": regex_pattern})
    else:
        match_conditions.extend([
            {"static_analysis.urls": regex_pattern},
            {"static_analysis.ips": regex_pattern},
            {"static_analysis.domains": regex_pattern},
        ])

    query = {"$or": match_conditions} if match_conditions else {}

    total = await db.analysis_results.count_documents(query)
    cursor = db.analysis_results.find(query).sort([("completed_at", -1)]).skip(skip).limit(limit)

    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        apk_id = doc.get("apk_id", "")
        if apk_id:
            try:
                apk = await db.apks.find_one({"_id": ObjectId(apk_id)})
                if apk:
                    apk["_id"] = str(apk["_id"])
                    doc["apk"] = apk
            except Exception:
                pass
        results.append(doc)

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "results": results,
    }
