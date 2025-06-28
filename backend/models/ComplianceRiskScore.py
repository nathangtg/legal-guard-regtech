from pydantic import BaseModel
from typing import List, Dict, Optional

class ComplianceRiskScore(BaseModel):
    financial_risk: float
    operational_risk: float
    reputation_risk: float
    overall_risk_level: str  # "low", "medium", "high"
    risk_explanation: str
    
    # Legacy fields for backward compatibility (optional)
    overall_score: Optional[int] = None  # 0-100
    financial_risk_estimate: Optional[float] = None
    violation_categories: Optional[List[str]] = None
    jurisdiction_risks: Optional[Dict[str, int]] = None