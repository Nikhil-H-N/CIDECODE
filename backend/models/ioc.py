from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field


class IOCDocument(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    type: str = ""
    value: str = ""
    threat_type: str = ""
    malware_family: Optional[str] = None
    confidence: float = 0.0
    source: str = ""
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)
    status: str = "active"
    geo: Optional[str] = None

    def to_dict(self) -> dict:
        data = self.model_dump(by_alias=True, exclude_none=True)
        for key in ("first_seen", "last_seen"):
            if isinstance(data.get(key), datetime):
                data[key] = data[key].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "IOCDocument":
        for key in ("first_seen", "last_seen"):
            if isinstance(data.get(key), str):
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)
