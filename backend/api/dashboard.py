from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from loguru import logger

from database.connection import get_database

router = APIRouter(tags=["Dashboard"])


@router.get("/dashboard/stats")
async def get_dashboard_stats(db=Depends(get_database)):
    try:
        total_analyzed = await db.analysis_results.count_documents({"status": "completed"})

        pipeline = [
            {"$match": {"status": "completed"}},
            {"$group": {
                "_id": "$threat_score.category",
                "count": {"$sum": 1},
            }},
        ]
        cursor = db.analysis_results.aggregate(pipeline)
        category_counts = {}
        async for doc in cursor:
            category_counts[doc["_id"] or "Unknown"] = doc["count"]

        critical_count = category_counts.get("Critical", 0)
        high_count = category_counts.get("High Risk", 0)
        medium_count = category_counts.get("Medium Risk", 0)
        low_count = category_counts.get("Low Risk", 0)
        safe_count = category_counts.get("Safe", 0)

        total_iocs = await db.iocs.count_documents({})
        active_iocs = await db.iocs.count_documents({"status": "active"})

        c2_detections = await db.analysis_results.count_documents({
            "c2_detection.suspicious_destinations": {"$gt": 0},
        })

        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        analyses_today = await db.analysis_results.count_documents({
            "completed_at": {"$gte": today_start},
        })

        family_pipeline = [
            {"$match": {"threat_score.ml_classification.prediction": {"$exists": True, "$ne": None}}},
            {"$group": {"_id": "$threat_score.ml_classification.prediction", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 1},
        ]
        family_cursor = db.analysis_results.aggregate(family_pipeline)
        most_common_family = None
        async for fam in family_cursor:
            most_common_family = fam["_id"]

        threats_by_category = [
            {"category": "Critical", "count": critical_count},
            {"category": "High Risk", "count": high_count},
            {"category": "Medium Risk", "count": medium_count},
            {"category": "Low Risk", "count": low_count},
            {"category": "Safe", "count": safe_count},
        ]

        return {
            "total_analyzed": total_analyzed,
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "safe_count": safe_count,
            "total_iocs": total_iocs,
            "active_iocs": active_iocs,
            "active_c2_detections": c2_detections,
            "analyses_today": analyses_today,
            "most_common_family": most_common_family,
            "threats_by_category": threats_by_category,
        }

    except Exception as e:
        logger.exception("Dashboard stats error")
        return {
            "total_analyzed": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "safe_count": 0,
            "total_iocs": 0,
            "active_iocs": 0,
            "active_c2_detections": 0,
            "analyses_today": 0,
            "most_common_family": None,
            "threats_by_category": [],
            "error": str(e),
        }


@router.get("/dashboard/recent")
async def get_recent_analyses(db=Depends(get_database)):
    cursor = db.analysis_results.find(
        {"status": "completed"},
        {
            "apk_id": 1,
            "status": 1,
            "threat_score.overall_score": 1,
            "threat_score.category": 1,
            "completed_at": 1,
            "static_analysis.urls": {"$slice": 5},
            "static_analysis.ips": {"$slice": 5},
        },
    ).sort([("completed_at", -1)]).limit(10)

    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        ts = doc.get("threat_score", {})
        sa = doc.get("static_analysis", {})
        results.append({
            "id": doc["_id"],
            "apk_id": doc.get("apk_id"),
            "score": ts.get("overall_score", 0) if ts else 0,
            "category": ts.get("category", "Unknown") if ts else "Unknown",
            "urls_found": len(sa.get("urls", [])),
            "ips_found": len(sa.get("ips", [])),
            "completed_at": doc.get("completed_at"),
        })

    return {"recent": results}


@router.get("/dashboard/threats-over-time")
async def get_threats_over_time(db=Depends(get_database)):
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    pipeline = [
        {"$match": {"completed_at": {"$gte": thirty_days_ago}, "status": "completed"}},
        {"$group": {
            "_id": {"$dateToString": {"format": "%Y-%m-%d", "date": "$completed_at"}},
            "count": {"$sum": 1},
        }},
        {"$sort": {"_id": 1}},
    ]

    data_points = []
    cursor = db.analysis_results.aggregate(pipeline)
    async for doc in cursor:
        data_points.append({"date": doc["_id"], "count": doc["count"]})

    return {"threats_over_time": data_points}


@router.get("/dashboard/ioc-summary")
async def get_ioc_summary(db=Depends(get_database)):
    pipeline = [
        {"$group": {
            "_id": "$type",
            "count": {"$sum": 1},
            "active": {"$sum": {"$cond": [{"$eq": ["$status", "active"]}, 1, 0]}},
        }},
        {"$sort": {"_id": 1}},
    ]

    summary = []
    cursor = db.iocs.aggregate(pipeline)
    async for doc in cursor:
        summary.append({
            "type": doc["_id"],
            "total": doc["count"],
            "active": doc["active"],
        })

    return {"ioc_summary": summary}
