import hashlib
import os
import tempfile
import zipfile

import aiofiles
from database.memory_db import ObjectId
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from loguru import logger

from config import settings
from database.connection import get_database
from models import APKDocument

router = APIRouter(tags=["Upload"])

ZIP_MAGIC = b"PK\x03\x04"
MAX_FILE_SIZE = settings.MAX_FILE_SIZE
CHUNK_SIZE = 1024 * 1024

VALID_EXTENSIONS = {".apk", ".zip"}


@router.post("/upload")
async def upload_apk(file: UploadFile = File(...), db=Depends(get_database)):
    ext = os.path.splitext(file.filename or "unknown")[1].lower()
    if ext not in VALID_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Allowed: {', '.join(VALID_EXTENSIONS)}",
        )

    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix="upload_", suffix=ext, dir=settings.UPLOAD_DIR)
    os.close(fd)

    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    total_size = 0
    magic = b""

    try:
        async with aiofiles.open(temp_path, "wb") as out:
            while True:
                chunk = await file.read(CHUNK_SIZE)
                if not chunk:
                    break
                if not magic:
                    magic = chunk[:4]
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"File too large ({total_size} bytes). Max: {MAX_FILE_SIZE} bytes",
                    )
                md5_hash.update(chunk)
                sha1_hash.update(chunk)
                sha256_hash.update(chunk)
                await out.write(chunk)

        if magic != ZIP_MAGIC:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Not a valid APK/ZIP file (ZIP magic bytes not found)",
            )

        try:
            with zipfile.ZipFile(temp_path, "r") as zf:
                bad_member = zf.testzip()
        except zipfile.BadZipFile:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Corrupt APK/ZIP file",
            )
        if bad_member:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Corrupt APK/ZIP member: {bad_member}",
            )

        md5 = md5_hash.hexdigest()
        sha1 = sha1_hash.hexdigest()
        sha256 = sha256_hash.hexdigest()

        existing = await db.apks.find_one({"sha256": sha256})
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="APK with this SHA256 already exists",
            )

        stored_name = f"{sha256}{ext}"
        file_path = os.path.normpath(os.path.join(settings.UPLOAD_DIR, stored_name))
        os.replace(temp_path, file_path)
    except Exception:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise

    apk_doc = APKDocument(
        original_filename=file.filename or "unknown.apk",
        stored_path=file_path,
        file_size_bytes=total_size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        status="pending",
    )

    result = await db.apks.insert_one(apk_doc.to_dict())
    apk_id = str(result.inserted_id)

    logger.info(f"APK uploaded: {file.filename} -> {apk_id} ({sha256[:16]}...)")

    return {
        "id": apk_id,
        "filename": file.filename,
        "size": total_size,
        "sha256": sha256,
        "status": "pending",
    }


@router.get("/upload/{apk_id}")
async def get_upload_status(apk_id: str, db=Depends(get_database)):
    try:
        doc = await db.apks.find_one({"_id": ObjectId(apk_id)})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid APK ID format")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="APK not found")

    doc["_id"] = str(doc["_id"])
    apk = APKDocument.from_dict(doc)

    return {
        "id": apk.id,
        "filename": apk.original_filename,
        "size": apk.file_size_bytes,
        "sha256": apk.sha256,
        "status": apk.status,
        "uploaded_at": apk.uploaded_at.isoformat() if hasattr(apk.uploaded_at, "isoformat") else str(apk.uploaded_at),
    }


@router.delete("/upload/{apk_id}")
async def delete_upload(apk_id: str, db=Depends(get_database)):
    try:
        doc = await db.apks.find_one({"_id": ObjectId(apk_id)})
    except Exception:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid APK ID format")

    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="APK not found")

    file_path = doc.get("stored_path", "")
    if file_path and os.path.isfile(file_path):
        try:
            os.remove(file_path)
            logger.info(f"Deleted file: {file_path}")
        except OSError as e:
            logger.warning(f"Failed to delete file {file_path}: {e}")

    await db.apks.delete_one({"_id": ObjectId(apk_id)})
    await db.analysis_results.delete_one({"apk_id": apk_id})

    return {"message": "APK and related data deleted", "id": apk_id}
