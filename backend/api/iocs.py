from datetime import datetime
from typing import List, Optional

from database.memory_db import ObjectId
from fastapi import APIRouter, Depends, HTTPException, Query, status
from loguru import logger
from pydantic import BaseModel

from config import settings
from database.connection import get_database
from models import IOCDocument

router = APIRouter(tags=["IOCs"])


class IOCCreateRequest(BaseModel):
    type: str
    value: str
    threat_type: str = "unknown"
    malware_family: Optional[str] = None
    confidence: float = 0.5
    source: str = "manual"
    tags: List[str] = []
    status: str = "active"
    geo: Optional[str] = None


class IOCImportRequest(BaseModel):
    iocs: List[IOCCreateRequest]


class IOCUpdateRequest(BaseModel):
    status: Optional[str] = None
    confidence: Optional[float] = None
    malware_family: Optional[str] = None
    tags: Optional[List[str]] = None
    geo: Optional[str] = None


@router.get("/iocs")
async def list_iocs(
    search: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db=Depends(get_database),
):
    query = {}
    if search:
        query["$or"] = [
            {"value": {"$regex": search, "$options": "i"}},
            {"threat_type": {"$regex": search, "$options": "i"}},
            {"malware_family": {"$regex": search, "$options": "i"}},
            {"tags": {"$regex": search, "$options": "i"}},
        ]
    if type:
        query["type"] = type
    if status:
        query["status"] = status

    skip = (page - 1) * limit
    total = await db.iocs.count_documents(query)

    cursor = db.iocs.find(query).sort([("last_seen", -1)]).skip(skip).limit(limit)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)

    return {
        "total": total,
        "page": page,
        "limit": limit,
        "iocs": results,
    }


@router.get("/iocs/{ioc_id}")
async def get_ioc(ioc_id: str, db=Depends(get_database)):
    try:
        doc = await db.iocs.find_one({"_id": ObjectId(ioc_id)})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid IOC ID")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    doc["_id"] = str(doc["_id"])
    return doc


@router.post("/iocs")
async def create_ioc(req: IOCCreateRequest, db=Depends(get_database)):
    existing = await db.iocs.find_one({"value": req.value})
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IOC with value '{req.value}' already exists",
        )

    doc = IOCDocument(
        type=req.type,
        value=req.value,
        threat_type=req.threat_type,
        malware_family=req.malware_family,
        confidence=req.confidence,
        source=req.source,
        tags=req.tags,
        status=req.status,
        geo=req.geo,
    )

    result = await db.iocs.insert_one(doc.to_dict())
    ioc_id = str(result.inserted_id)

    logger.info(f"IOC created: {req.type}:{req.value} ({ioc_id})")

    return {
        "id": ioc_id,
        "type": req.type,
        "value": req.value,
        "threat_type": req.threat_type,
        "status": req.status,
    }


@router.post("/iocs/import")
async def import_iocs(req: IOCImportRequest, db=Depends(get_database)):
    imported = 0
    skipped = 0
    errors = []

    for ioc_req in req.iocs:
        try:
            existing = await db.iocs.find_one({"value": ioc_req.value})
            if existing:
                skipped += 1
                continue

            doc = IOCDocument(
                type=ioc_req.type,
                value=ioc_req.value,
                threat_type=ioc_req.threat_type,
                malware_family=ioc_req.malware_family,
                confidence=ioc_req.confidence,
                source=ioc_req.source,
                tags=ioc_req.tags,
                status=ioc_req.status,
                geo=ioc_req.geo,
            )
            await db.iocs.insert_one(doc.to_dict())
            imported += 1
        except Exception as e:
            errors.append({"value": ioc_req.value, "error": str(e)})

    logger.info(f"IOC import: {imported} imported, {skipped} skipped, {len(errors)} errors")

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
        "total": len(req.iocs),
    }


@router.put("/iocs/{ioc_id}")
async def update_ioc(ioc_id: str, req: IOCUpdateRequest, db=Depends(get_database)):
    try:
        existing = await db.iocs.find_one({"_id": ObjectId(ioc_id)})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid IOC ID")

    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    update = {"last_seen": datetime.utcnow()}
    if req.status is not None:
        update["status"] = req.status
    if req.confidence is not None:
        update["confidence"] = req.confidence
    if req.malware_family is not None:
        update["malware_family"] = req.malware_family
    if req.tags is not None:
        update["tags"] = req.tags
    if req.geo is not None:
        update["geo"] = req.geo

    await db.iocs.update_one({"_id": ObjectId(ioc_id)}, {"$set": update})

    return {"message": "IOC updated", "id": ioc_id}


@router.delete("/iocs/{ioc_id}")
async def delete_ioc(ioc_id: str, db=Depends(get_database)):
    try:
        existing = await db.iocs.find_one({"_id": ObjectId(ioc_id)})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid IOC ID")

    if not existing:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IOC not found")

    await db.iocs.delete_one({"_id": ObjectId(ioc_id)})

    logger.info(f"IOC deleted: {ioc_id}")

    return {"message": "IOC deleted", "id": ioc_id}


@router.get("/iocs/stats")
async def get_ioc_stats(db=Depends(get_database)):
    type_pipeline = [
        {"$group": {"_id": "$type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    by_type = []
    cursor = db.iocs.aggregate(type_pipeline)
    async for doc in cursor:
        by_type.append({"type": doc["_id"], "count": doc["count"]})

    threat_pipeline = [
        {"$group": {"_id": "$threat_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    by_threat = []
    cursor = db.iocs.aggregate(threat_pipeline)
    async for doc in cursor:
        by_threat.append({"threat_type": doc["_id"], "count": doc["count"]})

    status_pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
    ]
    by_status = []
    cursor = db.iocs.aggregate(status_pipeline)
    async for doc in cursor:
        by_status.append({"status": doc["_id"], "count": doc["count"]})

    return {
        "total_iocs": await db.iocs.count_documents({}),
        "by_type": by_type,
        "by_threat_type": by_threat,
        "by_status": by_status,
    }
