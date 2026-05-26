from datetime import datetime
from typing import Optional, Dict
from pydantic import BaseModel, Field


class UserSettings(BaseModel):
    theme: str = "dark"
    notifications_enabled: bool = True
    default_report_template: str = "default"


class UserDocument(BaseModel):
    id: Optional[str] = Field(None, alias="_id")
    username: str = ""
    email: str = ""
    password_hash: str = ""
    role: str = "analyst"
    organization: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None
    is_active: bool = True
    api_key: Optional[str] = None
    settings: UserSettings = Field(default_factory=UserSettings)

    def to_dict(self) -> dict:
        data = self.model_dump(by_alias=True, exclude_none=True)
        for key in ("created_at", "last_login"):
            if isinstance(data.get(key), datetime):
                data[key] = data[key].isoformat()
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "UserDocument":
        for key in ("created_at", "last_login"):
            if isinstance(data.get(key), str):
                data[key] = datetime.fromisoformat(data[key])
        return cls(**data)
