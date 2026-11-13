from pydantic import BaseModel, Field
from typing import Literal, Optional, List

Language = Literal["en", "zh", "ms", "auto"]

class TextRequest(BaseModel):
    text: str = Field(min_length=3, max_length=20000)
    language: Language = "auto"
    save_case: bool = False

class URLRequest(BaseModel):
    url: str = Field(min_length=4, max_length=4096)
    save_case: bool = False

class Signal(BaseModel):
    code: str
    label: str
    detail: str
    severity: Literal["low", "medium", "high"]

class AnalysisResponse(BaseModel):
    analysis_id: Optional[str] = None
    modality: str
    risk_score: int
    risk_level: Literal["low", "medium", "high"]
    category: str
    language: str = "unknown"
    model_status: str
    explanation: str
    signals: List[Signal]
    recommendations: List[str]
    disclaimer: str
