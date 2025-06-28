from pydantic import BaseModel
from typing import List, Optional
from models.ComplianceRiskScore import ComplianceRiskScore

class ClauseFlag(BaseModel):
    clause_text: str
    issue_description: str
    severity: str = "medium"
    law_reference: str = ""
    recommendation: str = ""

class ComplianceFeedback(BaseModel):
    law_reference: str            # e.g., PDPA_MY, GDPR_EU
    missing_requirements: List[str]
    recommendations: List[str]
    risk_assessment: str = "Low risk"
    compliance_status: str = "compliant"  # compliant, partially_compliant, non_compliant, unknown

class ContractAnalysisResponse(BaseModel):
    summary: str
    clause_flags: List[ClauseFlag]
    compliance_feedback: List[ComplianceFeedback]
    risk_score: ComplianceRiskScore
    overall_compliance_status: str
    actionable_recommendations: List[str]
    jurisdiction_analyzed: str
    analysis_timestamp: str
