from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class APKDocument(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    original_filename: str = ""
    stored_path: str = ""
    file_size_bytes: int = 0
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    package_name: str = ""
    version_code: Optional[str] = None
    version_name: Optional[str] = None
    min_sdk_version: Optional[str] = None
    target_sdk_version: Optional[str] = None
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    uploaded_by: Optional[str] = None
    file_type_verified: bool = False
    integrity_verified: bool = False
    status: str = "pending"

    def to_dict(self) -> dict:
        data = self.model_dump(by_alias=True, exclude_none=True)
        data["uploaded_at"] = data["uploaded_at"].isoformat() if isinstance(data.get("uploaded_at"), datetime) else data.get("uploaded_at")
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "APKDocument":
        if data.get("uploaded_at") and isinstance(data["uploaded_at"], str):
            data["uploaded_at"] = datetime.fromisoformat(data["uploaded_at"])
        return cls(**data)
