from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    case_number: Optional[str] = None
    investigator: Optional[str] = None
    notes: Optional[str] = None


class EvidenceManifest(BaseModel):
    type: str = ""
    path: str = ""
    description: str = ""
    hash: str = ""
    collected_at: datetime = Field(default_factory=datetime.utcnow)


class ChainOfCustody(BaseModel):
    action: str = ""
    performed_by: str = ""
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    notes: Optional[str] = None


class ReportDocument(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    apk_id: str = ""
    analysis_id: str = ""
    template_used: str = "default"
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    file_path: Optional[str] = None
    sha256: Optional[str] = None
    metadata: ReportMetadata = Field(default_factory=ReportMetadata)
    evidence_manifest: List[EvidenceManifest] = Field(default_factory=list)
    chain_of_custody: List[ChainOfCustody] = Field(default_factory=list)

    def to_dict(self) -> dict:
        data = self.model_dump(by_alias=True, exclude_none=True)
        data["generated_at"] = data["generated_at"].isoformat() if isinstance(data.get("generated_at"), datetime) else data.get("generated_at")
        for item in data.get("evidence_manifest", []):
            if isinstance(item.get("collected_at"), datetime):
                item["collected_at"] = item["collected_at"].isoformat()
        for item in data.get("chain_of_custody", []):
            if isinstance(item.get("timestamp"), datetime):
                item["timestamp"] = item["timestamp"].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "ReportDocument":
        if isinstance(data.get("generated_at"), str):
            data["generated_at"] = datetime.fromisoformat(data["generated_at"])
        for item in data.get("evidence_manifest", []):
            if isinstance(item.get("collected_at"), str):
                item["collected_at"] = datetime.fromisoformat(item["collected_at"])
        for item in data.get("chain_of_custody", []):
            if isinstance(item.get("timestamp"), str):
                item["timestamp"] = datetime.fromisoformat(item["timestamp"])
        return cls(**data)
