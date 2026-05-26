from datetime import datetime
from typing import Optional, List, Dict
from pydantic import BaseModel, Field


class StaticAnalysis(BaseModel):
    permissions: List[Dict[str, str]] = Field(default_factory=list)
    manifest: Dict = Field(default_factory=dict)
    strings: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    certificate: Dict = Field(default_factory=dict)
    entropy: float = 0.0
    native_libs: List[str] = Field(default_factory=list)
    anti_analysis: List[str] = Field(default_factory=list)
    permission_usage: Dict[str, List[str]] = Field(default_factory=dict)


class DynamicAnalysis(BaseModel):
    enabled: bool = False
    traffic_log: List[Dict] = Field(default_factory=list)
    file_system_changes: List[str] = Field(default_factory=list)
    background_services_detected: List[str] = Field(default_factory=list)
    microphone_access: bool = False
    camera_access: bool = False
    sms_behavior: List[str] = Field(default_factory=list)
    hidden_processes: List[str] = Field(default_factory=list)


class C2Detection(BaseModel):
    total_destinations: int = 0
    suspicious_destinations: int = 0
    ioc_matches: List[str] = Field(default_factory=list)
    beaconing: List[Dict] = Field(default_factory=list)
    dga_domains: List[str] = Field(default_factory=list)
    geolocation: List[Dict] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)


class ThreatScoreComponents(BaseModel):
    permissions_score: float = 0.0
    static_analysis_score: float = 0.0
    dynamic_analysis_score: float = 0.0
    c2_score: float = 0.0
    yara_score: float = 0.0
    ml_score: float = 0.0


class MLClassification(BaseModel):
    model_used: str = ""
    prediction: str = ""
    confidence: float = 0.0
    probabilities: Dict[str, float] = Field(default_factory=dict)


class ThreatScore(BaseModel):
    overall_score: float = 0.0
    category: str = "Unknown"
    components: ThreatScoreComponents = Field(default_factory=ThreatScoreComponents)
    ml_classification: Optional[MLClassification] = None


class YaraMatch(BaseModel):
    rule_name: str = ""
    description: str = ""
    severity: str = "medium"
    matched_strings: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)


class AnalysisResult(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    apk_id: str = ""
    status: str = "pending"
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    static_analysis: StaticAnalysis = Field(default_factory=StaticAnalysis)
    dynamic_analysis: DynamicAnalysis = Field(default_factory=DynamicAnalysis)
    c2_detection: C2Detection = Field(default_factory=C2Detection)
    threat_score: ThreatScore = Field(default_factory=ThreatScore)
    yara_matches: List[YaraMatch] = Field(default_factory=list)

    def to_dict(self) -> dict:
        data = self.model_dump(by_alias=True, exclude_none=True)
        for key in ("started_at", "completed_at"):
            if isinstance(data.get(key), datetime):
                data[key] = data[key].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "AnalysisResult":
        for key in ("started_at", "completed_at"):
            if isinstance(data.get(key), str):
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)
