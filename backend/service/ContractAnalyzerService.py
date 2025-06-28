import json
import logging
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dotenv import load_dotenv

# Load environment variables from .env file
env_path = Path(__file__).parent.parent.parent / '.env'
load_dotenv(env_path)

from models.ContractAnalysisModel import ContractAnalysisRequest
from models.ContractAnalysisResponseModel import ContractAnalysisResponse, ClauseFlag, ComplianceFeedback
from models.ComplianceRiskScore import ComplianceRiskScore
from utils.law_loader import LawLoader
from service.RegulatoryEngineService import RegulatoryEngineService
from utils.ai_client import WatsonXClient, WatsonXConfig
from utils.ai_client.exceptions import ConfigurationError, APIError, AuthenticationError 

logger = logging.getLogger(__name__)

class ContractAnalyzerService:
    def __init__(self):
        """
        Initialize the contract analyzer with data-driven approach using JSON law files.
        """
        self.law_loader = LawLoader()
        self.regulatory_engine = RegulatoryEngineService(self.law_loader)
        self.watsonx_client = None
        
        # Load law pattern configurations from JSON files
        self._load_law_patterns()
        
        # Initialize IBM WatsonX Granite client
        try:
            config = WatsonXConfig.from_environment()
            self.watsonx_client = WatsonXClient(config)
            logger.info("IBM WatsonX Granite client initialized successfully.")
        except ConfigurationError as e:
            logger.warning(f"Failed to initialize WatsonX client due to configuration: {e}")
            self.watsonx_client = None
        except Exception as e:
            logger.error(f"Failed to initialize WatsonX client: {e}")
            self.watsonx_client = None

    def _load_law_patterns(self):
        """
        Load contract analysis patterns from JSON law files to make analysis data-driven.
        """
        self.law_patterns = {}
        self.risk_configurations = {}
        
        # Get all available jurisdictions and their laws
        all_jurisdictions = ["MY", "SG", "EU", "US"]
        
        for jurisdiction in all_jurisdictions:
            laws = self.law_loader.get_laws_for_jurisdiction(jurisdiction)
            
            for law_id, law_data in laws.items():
                if not law_data:
                    continue
                    
                # Extract contract analysis patterns from law data
                patterns = self._extract_patterns_from_law_data(law_id, law_data)
                if patterns:
                    self.law_patterns[law_id] = patterns
                
                # Extract risk configuration
                risk_config = self._extract_risk_config_from_law_data(law_id, law_data)
                if risk_config:
                    self.risk_configurations[law_id] = risk_config
        
        logger.info(f"Loaded patterns for {len(self.law_patterns)} laws")

    def _extract_patterns_from_law_data(self, law_id: str, law_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract contract analysis patterns from law JSON data.
        This makes the analysis completely data-driven instead of hardcoded.
        """
        patterns = {
            "required_clauses": [],
            "prohibited_patterns": [],
            "risk_indicators": [],
            "compliance_checks": []
        }
        
        # Extract required clauses from law requirements
        if "requirements" in law_data:
            for req_key, req_data in law_data["requirements"].items():
                if isinstance(req_data, dict):
                    description = req_data.get("description", "")
                    keywords = req_data.get("keywords", [])
                    
                    patterns["required_clauses"].append({
                        "requirement_id": req_key,
                        "description": description,
                        "keywords": keywords,
                        "severity": req_data.get("severity", "medium")
                    })
        
        # Extract prohibited patterns from violations
        if "violations" in law_data:
            for violation in law_data["violations"]:
                if isinstance(violation, dict):
                    patterns["prohibited_patterns"].append({
                        "violation_type": violation.get("type", ""),
                        "description": violation.get("description", ""),
                        "keywords": violation.get("keywords", []),
                        "severity": violation.get("severity", "high")
                    })
        
        # Extract risk indicators from penalties
        if "penalties" in law_data:
            penalties = law_data["penalties"]
            if isinstance(penalties, dict):
                risk_level = penalties.get("risk_level", "medium")
                risk_indicators = penalties.get("indicators", [])
                
                patterns["risk_indicators"] = {
                    "risk_level": risk_level,
                    "indicators": risk_indicators,
                    "financial_range": penalties.get("financial_range", {}),
                    "enforcement_likelihood": penalties.get("enforcement_likelihood", "medium")
                }
        
        # Extract compliance checks from specific law content
        patterns["compliance_checks"] = self._build_law_specific_checks(law_id, law_data)
        
        return patterns

    def _build_law_specific_checks(self, law_id: str, law_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build law-specific compliance checks based on the law's JSON data.
        """
        checks = []
        
        # Build checks based on law type
        if "PDPA" in law_id or "GDPR" in law_id or "CCPA" in law_id:
            checks.extend(self._build_privacy_law_checks(law_id, law_data))
        elif "EMPLOYMENT" in law_id:
            checks.extend(self._build_employment_law_checks(law_id, law_data))
        
        return checks

    def _build_privacy_law_checks(self, law_id: str, law_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build privacy law specific checks from JSON data.
        """
        checks = []
        
        # Common privacy law checks
        privacy_concepts = [
            {
                "concept": "consent_mechanism",
                "keywords": ["consent", "agree", "permission", "authorization"],
                "required_elements": ["opt-out", "withdrawal", "specific", "informed"],
                "severity": "high"
            },
            {
                "concept": "data_retention",
                "keywords": ["retention", "store", "keep", "maintain"],
                "prohibited_elements": ["indefinite", "unlimited", "perpetual", "forever"],
                "severity": "high"
            },
            {
                "concept": "breach_notification",
                "keywords": ["breach", "incident", "unauthorized", "security"],
                "required_elements": ["72 hours", "notification", "report", "authority"],
                "severity": "high"
            },
            {
                "concept": "data_transfer",
                "keywords": ["transfer", "transmit", "share", "disclose"],
                "required_elements": ["adequate protection", "safeguards", "standard contractual clauses"],
                "severity": "medium"
            },
            {
                "concept": "individual_rights",
                "keywords": ["access", "rectification", "erasure", "portability"],
                "required_elements": ["request", "response time", "verification"],
                "severity": "medium"
            }
        ]
        
        # Add law-specific requirements from JSON
        if "requirements" in law_data:
            for req_key, req_data in law_data["requirements"].items():
                if isinstance(req_data, dict):
                    checks.append({
                        "concept": req_key,
                        "description": req_data.get("description", ""),
                        "keywords": req_data.get("keywords", []),
                        "severity": req_data.get("severity", "medium"),
                        "law_specific": True
                    })
        
        checks.extend(privacy_concepts)
        return checks

    def _build_employment_law_checks(self, law_id: str, law_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build employment law specific checks from JSON data.
        """
        checks = []
        
        employment_concepts = [
            {
                "concept": "termination_notice",
                "keywords": ["termination", "notice", "end", "cease"],
                "required_elements": ["minimum period", "weeks", "advance notice"],
                "severity": "high"
            },
            {
                "concept": "overtime_compensation",
                "keywords": ["overtime", "extra hours", "additional work"],
                "required_elements": ["compensation", "rate", "payment"],
                "severity": "medium"
            },
            {
                "concept": "working_hours",
                "keywords": ["working hours", "work time", "schedule"],
                "prohibited_elements": ["excessive", "unlimited"],
                "severity": "medium"
            }
        ]
        
        # Add law-specific requirements from JSON
        if "requirements" in law_data:
            for req_key, req_data in law_data["requirements"].items():
                if isinstance(req_data, dict):
                    checks.append({
                        "concept": req_key,
                        "description": req_data.get("description", ""),
                        "keywords": req_data.get("keywords", []),
                        "severity": req_data.get("severity", "medium"),
                        "law_specific": True
                    })
        
        checks.extend(employment_concepts)
        return checks

    def _extract_risk_config_from_law_data(self, law_id: str, law_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract risk configuration from law JSON data for dynamic risk calculation.
        """
        risk_config = {
            "base_risk_amount": 10000,  # Default
            "risk_multipliers": {},
            "severity_weights": {"high": 1.0, "medium": 0.6, "low": 0.3}
        }
        
        if "penalties" in law_data:
            penalties = law_data["penalties"]
            if isinstance(penalties, dict):
                # Extract financial risk from penalty data
                financial_range = penalties.get("financial_range", {})
                if financial_range:
                    min_penalty = financial_range.get("min", 1000)
                    max_penalty = financial_range.get("max", 50000)
                    risk_config["base_risk_amount"] = (min_penalty + max_penalty) / 2
                
                # Set risk level multipliers
                risk_level = penalties.get("risk_level", "medium").lower()
                risk_multiplier = {
                    "very high": 3.0,
                    "high": 2.0,
                    "medium": 1.0,
                    "low": 0.5,
                    "very low": 0.2
                }.get(risk_level, 1.0)
                
                risk_config["risk_multipliers"]["base"] = risk_multiplier
        
        return risk_config

    async def analyze_contract(self, request: ContractAnalysisRequest) -> ContractAnalysisResponse:
        """
        Main contract analysis orchestrator using data-driven approach with IBM Granite.
        """
        try:
            jurisdiction = request.jurisdiction or "MY"
            
            # Get compliance checklist from regulatory engine
            compliance_checklist = self.regulatory_engine.get_compliance_checklist(
                jurisdiction=jurisdiction,
                contract_type=self._detect_contract_type(request.text)
            )

            # Use IBM WatsonX Granite for intelligent analysis
            use_granite_ai = (self.watsonx_client is not None and 
                             os.getenv("IBM_API_KEY") and 
                             os.getenv("WATSONX_PROJECT_ID"))

            if use_granite_ai:
                try:
                    logger.info("Analyzing contract with IBM Granite model")
                    ai_response_text = await self._analyze_with_granite(
                        contract_text=request.text,
                        compliance_checklist=compliance_checklist,
                        jurisdiction=jurisdiction
                    )
                    
                    # Validate and enhance Granite's response if needed
                    if self._is_response_insufficient(ai_response_text):
                        logger.info("Enhancing Granite response with data-driven analysis")
                        ai_response_text = await self._enhance_with_data_driven_analysis(
                            granite_response=ai_response_text,
                            contract_text=request.text,
                            jurisdiction=jurisdiction
                        )
                        
                except (APIError, AuthenticationError) as e:
                    logger.error(f"Granite API error: {e}")
                    ai_response_text = await self._fallback_data_driven_analysis(
                        request.text, jurisdiction
                    )
                except Exception as e:
                    logger.error(f"Unexpected Granite error: {e}")
                    ai_response_text = await self._fallback_data_driven_analysis(
                        request.text, jurisdiction
                    )
            else:
                logger.info("Using data-driven analysis (Granite not available)")
                ai_response_text = await self._fallback_data_driven_analysis(
                    request.text, jurisdiction
                )

            # Parse and structure the response
            return self._create_structured_response(ai_response_text, jurisdiction)

        except Exception as e:
            logger.error(f"Contract analysis failed: {str(e)}")
            raise

    async def _analyze_with_granite(self, contract_text: str, compliance_checklist: Dict[str, Any], 
                                   jurisdiction: str) -> str:
        """
        Use IBM Granite model for intelligent contract analysis with enhanced prompting.
        """
        # Build data-driven context for Granite
        applicable_laws = self.law_loader.get_laws_for_jurisdiction(jurisdiction)
        law_contexts = []
        
        for law_id, law_data in applicable_laws.items():
            if law_id in self.law_patterns:
                patterns = self.law_patterns[law_id]
                
                # Safely extract requirements with error handling
                key_requirements = []
                if patterns.get("required_clauses") and isinstance(patterns["required_clauses"], list):
                    for req in patterns["required_clauses"]:
                        if isinstance(req, dict) and "description" in req:
                            key_requirements.append(req["description"])
                
                # Safely extract prohibited practices with error handling
                prohibited_practices = []
                if patterns.get("prohibited_patterns") and isinstance(patterns["prohibited_patterns"], list):
                    for viol in patterns["prohibited_patterns"]:
                        if isinstance(viol, dict) and "description" in viol:
                            prohibited_practices.append(viol["description"])
                
                # Safely extract risk level
                risk_indicators = patterns.get("risk_indicators", {})
                if isinstance(risk_indicators, dict):
                    risk_level = risk_indicators.get("risk_level", "medium")
                else:
                    risk_level = "medium"
                
                law_context = {
                    "law_id": law_id,
                    "name": law_data.get("name", law_id),
                    "description": law_data.get("description", ""),
                    "key_requirements": key_requirements,
                    "prohibited_practices": prohibited_practices,
                    "risk_level": risk_level
                }
                law_contexts.append(law_context)

        # Enhanced prompt for Granite with legal domain expertise
        granite_prompt = self._build_granite_legal_prompt(
            contract_text, law_contexts, compliance_checklist
        )
        
        # Call Granite with legal-specific configuration
        response = self.watsonx_client.analyze_contract_advanced(
            prompt=granite_prompt,
            max_tokens=2048,
            temperature=0.1,  # Low temperature for consistent legal analysis
            top_p=0.9
        )
        
        return response

    def _build_granite_legal_prompt(self, contract_text: str, law_contexts: List[Dict], 
                                   compliance_checklist: Dict[str, Any]) -> str:
        """
        Build a comprehensive legal analysis prompt for IBM Granite model.
        """
        prompt = f"""You are an expert legal contract analyst with deep expertise in compliance law. 
Analyze the following contract against applicable legal requirements and provide a comprehensive JSON response.

APPLICABLE LAWS AND REQUIREMENTS:
"""
        
        for law_context in law_contexts:
            prompt += f"""
{law_context['law_id']} - {law_context['name']}:
- Description: {law_context['description']}
- Key Requirements: {'; '.join(law_context['key_requirements'][:3])}
- Risk Level: {law_context['risk_level']}
"""

        prompt += f"""
CONTRACT TO ANALYZE:
{contract_text}

ANALYSIS REQUIREMENTS:
1. Identify specific clauses that violate or fail to meet legal requirements
2. Flag high-risk provisions that could lead to regulatory penalties
3. Provide specific compliance gaps with reference to applicable laws
4. Include actionable recommendations for remediation

RESPONSE FORMAT (JSON):
{{
    "summary": "Comprehensive analysis summary highlighting key risks and compliance status",
    "flagged_clauses": [
        {{
            "clause_text": "Exact text of problematic clause",
            "issue": "Specific legal issue and law reference",
            "severity": "high|medium|low",
            "law_reference": "Specific law ID"
        }}
    ],
    "compliance_issues": [
        {{
            "law": "LAW_ID",
            "missing_requirements": ["Specific missing requirement 1", "Specific missing requirement 2"],
            "recommendations": ["Specific recommendation 1", "Specific recommendation 2"],
            "risk_assessment": "Description of compliance risk"
        }}
    ]
}}

Provide detailed, specific analysis focusing on actual compliance gaps and legal risks."""

        return prompt

    async def _enhance_with_data_driven_analysis(self, granite_response: str, 
                                               contract_text: str, jurisdiction: str) -> str:
        """
        Enhance Granite's response using data-driven analysis from JSON law files.
        """
        try:
            granite_data = json.loads(granite_response) if granite_response else {}
        except json.JSONDecodeError:
            granite_data = {}

        # Perform data-driven analysis
        data_driven_analysis = await self._perform_data_driven_analysis(
            contract_text, jurisdiction
        )
        
        # Merge Granite insights with data-driven analysis
        enhanced_response = self._merge_analysis_results(granite_data, data_driven_analysis)
        
        return json.dumps(enhanced_response)

    async def _perform_data_driven_analysis(self, contract_text: str, 
                                          jurisdiction: str) -> Dict[str, Any]:
        """
        Perform comprehensive contract analysis using patterns from JSON law files.
        """
        flagged_clauses = []
        compliance_issues = []
        
        # Get applicable laws for jurisdiction
        applicable_laws = self.law_loader.get_laws_for_jurisdiction(jurisdiction)
        
        # Analyze contract against each applicable law
        for law_id, law_data in applicable_laws.items():
            if law_id not in self.law_patterns:
                continue
                
            patterns = self.law_patterns[law_id]
            
            # Check for missing required clauses
            missing_requirements, recommendations = self._check_law_compliance(
                contract_text, law_id, patterns, law_data
            )
            
            # Find problematic clauses
            law_flagged_clauses = self._find_problematic_clauses(
                contract_text, law_id, patterns
            )
            
            flagged_clauses.extend(law_flagged_clauses)
            
            if missing_requirements:
                compliance_issues.append({
                    "law": law_id,
                    "missing_requirements": missing_requirements,
                    "recommendations": recommendations,
                    "risk_assessment": self._assess_law_risk(law_id, len(missing_requirements))
                })

        # Generate comprehensive summary
        summary = self._generate_data_driven_summary(
            flagged_clauses, compliance_issues, jurisdiction
        )

        return {
            "summary": summary,
            "flagged_clauses": flagged_clauses,
            "compliance_issues": compliance_issues
        }

    def _check_law_compliance(self, contract_text: str, law_id: str, 
                             patterns: Dict[str, Any], law_data: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        """
        Check contract compliance against specific law using data-driven patterns.
        """
        missing_requirements = []
        recommendations = []
        text_lower = contract_text.lower()
        
        # Check compliance using law-specific patterns
        compliance_checks = patterns.get("compliance_checks", [])
        
        # Ensure compliance_checks is a list
        if not isinstance(compliance_checks, list):
            compliance_checks = []
        
        for check in compliance_checks:
            if not isinstance(check, dict):
                continue
                
            concept = check.get("concept", "")
            keywords = check.get("keywords", [])
            required_elements = check.get("required_elements", [])
            prohibited_elements = check.get("prohibited_elements", [])
            
            # Ensure keywords, required_elements, and prohibited_elements are lists
            if not isinstance(keywords, list):
                keywords = []
            if not isinstance(required_elements, list):
                required_elements = []
            if not isinstance(prohibited_elements, list):
                prohibited_elements = []
            
            # Check if concept is mentioned in contract
            concept_found = any(keyword.lower() in text_lower for keyword in keywords)
            
            if concept_found:
                # Check for required elements
                for required in required_elements:
                    if required.lower() not in text_lower:
                        missing_requirements.append(
                            f"Missing {required} for {concept} as required by {law_id}"
                        )
                        recommendations.append(
                            f"Add {required} clause to ensure {concept} compliance with {law_id}"
                        )
                
                # Check for prohibited elements
                for prohibited in prohibited_elements:
                    if prohibited.lower() in text_lower:
                        missing_requirements.append(
                            f"Contract contains prohibited {prohibited} in {concept} section violating {law_id}"
                        )
                        recommendations.append(
                            f"Remove or modify {prohibited} clause to comply with {law_id}"
                        )
            else:
                # Concept not found at all
                if check.get("law_specific", False) or check["severity"] == "high":
                    missing_requirements.append(
                        f"Contract lacks required {concept} provisions for {law_id} compliance"
                    )
                    recommendations.append(
                        f"Add comprehensive {concept} clauses as required by {law_id}"
                    )

        return missing_requirements, recommendations

    def _find_problematic_clauses(self, contract_text: str, law_id: str, 
                                 patterns: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Find specific problematic clauses using data-driven pattern matching.
        """
        flagged_clauses = []
        
        # Check prohibited patterns
        prohibited_patterns = patterns.get("prohibited_patterns", [])
        
        # Ensure prohibited_patterns is a list
        if not isinstance(prohibited_patterns, list):
            prohibited_patterns = []
        
        for pattern in prohibited_patterns:
            if not isinstance(pattern, dict):
                continue
                
            violation_type = pattern.get("violation_type", "")
            keywords = pattern.get("keywords", [])
            severity = pattern.get("severity", "medium")
            description = pattern.get("description", "")
            
            # Ensure keywords is a list
            if not isinstance(keywords, list):
                keywords = []
            
            for keyword in keywords:
                if keyword.lower() in contract_text.lower():
                    clause_text = self._extract_clause_context(contract_text, keyword)
                    if clause_text:
                        flagged_clauses.append({
                            "clause_text": clause_text,
                            "issue": f"{law_id}: {description}",
                            "severity": severity,
                            "law_reference": law_id
                        })
                        break  # Only flag once per pattern

        return flagged_clauses

    def _extract_clause_context(self, contract_text: str, keyword: str) -> str:
        """
        Extract meaningful clause context around a keyword.
        """
        import re
        
        # Find the keyword position
        text_lower = contract_text.lower()
        keyword_pos = text_lower.find(keyword.lower())
        
        if keyword_pos == -1:
            return ""
        
        # Extract surrounding context (about 200 characters on each side)
        start = max(0, keyword_pos - 200)
        end = min(len(contract_text), keyword_pos + len(keyword) + 200)
        
        context = contract_text[start:end].strip()
        
        # Try to find complete sentences
        sentences = re.split(r'[.!?]+\s+', context)
        
        # Find the sentence containing the keyword
        for sentence in sentences:
            if keyword.lower() in sentence.lower():
                return sentence.strip() + "."
        
        # Fallback to the context
        return context

    def _assess_law_risk(self, law_id: str, violation_count: int) -> str:
        """
        Assess risk level based on law configuration and violation count.
        """
        if law_id not in self.risk_configurations:
            return "Medium risk - compliance gaps identified"
        
        risk_config = self.risk_configurations[law_id]
        base_multiplier = risk_config.get("risk_multipliers", {}).get("base", 1.0)
        
        if base_multiplier >= 2.0 and violation_count > 2:
            return "High risk - multiple serious compliance violations"
        elif base_multiplier >= 1.5 or violation_count > 3:
            return "Medium-high risk - significant compliance concerns"
        elif violation_count > 1:
            return "Medium risk - compliance improvements needed"
        else:
            return "Low-medium risk - minor compliance adjustments required"

    def _generate_data_driven_summary(self, flagged_clauses: List[Dict], 
                                     compliance_issues: List[Dict], jurisdiction: str) -> str:
        """
        Generate comprehensive summary based on data-driven analysis results.
        """
        total_issues = len(flagged_clauses) + len(compliance_issues)
        high_severity_count = len([c for c in flagged_clauses if c.get("severity") == "high"])
        
        if total_issues == 0:
            return f"Contract analysis complete for {jurisdiction} jurisdiction. No significant compliance issues identified."
        
        summary_parts = []
        
        # Risk level assessment
        if high_severity_count > 2 or total_issues > 6:
            summary_parts.append("HIGH RISK: Contract contains significant compliance violations")
        elif high_severity_count > 0 or total_issues > 3:
            summary_parts.append("MEDIUM RISK: Contract has compliance issues requiring attention")
        else:
            summary_parts.append("LOW-MEDIUM RISK: Minor compliance improvements needed")
        
        # Specific findings
        if flagged_clauses:
            summary_parts.append(f"Identified {len(flagged_clauses)} problematic clauses")
            if high_severity_count > 0:
                summary_parts.append(f"including {high_severity_count} high-severity issues")
        
        if compliance_issues:
            affected_laws = [issue["law"] for issue in compliance_issues]
            summary_parts.append(f"Compliance gaps found across {len(affected_laws)} legal frameworks: {', '.join(affected_laws)}")
        
        return ". ".join(summary_parts) + "."

    def _merge_analysis_results(self, granite_data: Dict[str, Any], 
                               data_driven_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Intelligently merge Granite AI results with data-driven analysis.
        """
        # Use Granite's summary if meaningful, otherwise use data-driven
        if (granite_data.get("summary") and 
            len(granite_data["summary"]) > 50 and
            "error" not in granite_data["summary"].lower()):
            summary = granite_data["summary"]
        else:
            summary = data_driven_data["summary"]
        
        # Merge flagged clauses (avoid duplicates)
        granite_clauses = granite_data.get("flagged_clauses", [])
        data_clauses = data_driven_data.get("flagged_clauses", [])
        
        merged_clauses = granite_clauses.copy()
        granite_issues = {clause.get("issue", "") for clause in granite_clauses}
        
        for clause in data_clauses:
            if clause.get("issue", "") not in granite_issues:
                merged_clauses.append(clause)
        
        # Merge compliance issues by law
        granite_compliance = granite_data.get("compliance_issues", [])
        data_compliance = data_driven_data.get("compliance_issues", [])
        
        compliance_by_law = {}
        
        # Add Granite's compliance issues
        for issue in granite_compliance:
            law = issue.get("law", "")
            if law:
                compliance_by_law[law] = issue
        
        # Merge with data-driven compliance issues
        for issue in data_compliance:
            law = issue.get("law", "")
            if law:
                if law in compliance_by_law:
                    # Combine requirements and recommendations
                    existing = compliance_by_law[law]
                    existing["missing_requirements"] = list(set(
                        existing.get("missing_requirements", []) + 
                        issue.get("missing_requirements", [])
                    ))
                    existing["recommendations"] = list(set(
                        existing.get("recommendations", []) + 
                        issue.get("recommendations", [])
                    ))
                    # Use data-driven risk assessment if Granite doesn't have one
                    if not existing.get("risk_assessment") and issue.get("risk_assessment"):
                        existing["risk_assessment"] = issue["risk_assessment"]
                else:
                    compliance_by_law[law] = issue
        
        return {
            "summary": summary,
            "flagged_clauses": merged_clauses,
            "compliance_issues": list(compliance_by_law.values())
        }

    async def _fallback_data_driven_analysis(self, contract_text: str, jurisdiction: str) -> str:
        """
        Fallback to pure data-driven analysis when Granite is not available.
        """
        logger.info("Performing fallback data-driven analysis")
        analysis_result = await self._perform_data_driven_analysis(contract_text, jurisdiction)
        return json.dumps(analysis_result)

    def _detect_contract_type(self, contract_text: str) -> str:
        """
        Detect contract type from content for better law selection.
        """
        text_lower = contract_text.lower()
        
        type_indicators = {
            "employment": ["employee", "employer", "salary", "working hours", "termination", "job"],
            "data_processing": ["data", "personal information", "processing", "privacy", "gdpr"],
            "service": ["service", "provider", "client", "deliverable", "performance"],
            "purchase": ["purchase", "buy", "sell", "goods", "delivery", "payment"],
            "license": ["license", "intellectual property", "copyright", "usage", "rights"],
            "nda": ["confidential", "non-disclosure", "proprietary", "trade secret"]
        }
        
        for contract_type, keywords in type_indicators.items():
            if sum(1 for keyword in keywords if keyword in text_lower) >= 2:
                return contract_type
        
        return "generic"

    def _is_response_insufficient(self, response: str) -> bool:
        """
        Check if AI response needs enhancement using data-driven criteria.
        """
        if not response or len(response.strip()) < 100:
            return True
        
        try:
            data = json.loads(response)
            
            # Check if response is empty or minimal
            if (not data.get("flagged_clauses") and 
                not data.get("compliance_issues") and 
                len(data.get("summary", "")) < 50):
                return True
            
            # Check if summary is generic or contains error indicators
            summary = data.get("summary", "").lower()
            if any(indicator in summary for indicator in ["error", "failed", "unable", "cannot"]):
                return True
            
            return False
            
        except json.JSONDecodeError:
            return True

    def _create_structured_response(self, analysis_text: str, jurisdiction: str) -> ContractAnalysisResponse:
        """
        Create structured response from analysis text with comprehensive risk scoring.
        """
        try:
            # Parse the analysis JSON
            if analysis_text.strip():
                try:
                    analysis_data = json.loads(analysis_text)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse analysis JSON, creating fallback response")
                    analysis_data = self._create_fallback_analysis_data(analysis_text, jurisdiction)
            else:
                analysis_data = self._create_empty_analysis_data(jurisdiction)
            
            # Extract components with safety checks
            summary = analysis_data.get("summary", "Contract analysis completed.")
            flagged_clauses_data = analysis_data.get("flagged_clauses", [])
            compliance_issues_data = analysis_data.get("compliance_issues", [])
            
            # Ensure data is in expected format
            if not isinstance(flagged_clauses_data, list):
                flagged_clauses_data = []
            if not isinstance(compliance_issues_data, list):
                compliance_issues_data = []
            
            # Create clause flags
            clause_flags = []
            for clause_data in flagged_clauses_data:
                if not isinstance(clause_data, dict):
                    continue
                clause_flag = ClauseFlag(
                    clause_text=clause_data.get("clause_text", ""),
                    issue_description=clause_data.get("issue", ""),
                    severity=clause_data.get("severity", "medium"),
                    law_reference=clause_data.get("law_reference", ""),
                    recommendation=self._generate_clause_recommendation(clause_data)
                )
                clause_flags.append(clause_flag)
            
            # Create compliance feedback
            compliance_feedback = []
            for compliance_data in compliance_issues_data:
                if not isinstance(compliance_data, dict):
                    continue
                    
                feedback = ComplianceFeedback(
                    law_reference=compliance_data.get("law", ""),
                    missing_requirements=compliance_data.get("missing_requirements", []),
                    recommendations=compliance_data.get("recommendations", []),
                    risk_assessment=compliance_data.get("risk_assessment", "Low risk"),
                    compliance_status="non_compliant" if compliance_data.get("missing_requirements") else "compliant"
                )
                compliance_feedback.append(feedback)
            
            # Calculate comprehensive risk score
            risk_score = self._calculate_comprehensive_risk_score(
                clause_flags, compliance_feedback, jurisdiction
            )
            
            # Determine overall compliance status
            overall_status = self._determine_overall_compliance_status(
                clause_flags, compliance_feedback
            )
            
            # Generate actionable recommendations
            actionable_recommendations = self._generate_actionable_recommendations(
                clause_flags, compliance_feedback, jurisdiction
            )
            
            return ContractAnalysisResponse(
                summary=summary,
                clause_flags=clause_flags,
                compliance_feedback=compliance_feedback,
                risk_score=risk_score,
                overall_compliance_status=overall_status,
                actionable_recommendations=actionable_recommendations,
                jurisdiction_analyzed=jurisdiction,
                analysis_timestamp=self._get_current_timestamp()
            )
            
        except Exception as e:
            logger.error(f"Failed to create structured response: {str(e)}")
            return self._create_error_response(str(e), jurisdiction)

    def _generate_clause_recommendation(self, clause_data: Dict[str, Any]) -> str:
        """
        Generate specific recommendation for a flagged clause.
        """
        issue = clause_data.get("issue", "")
        severity = clause_data.get("severity", "medium")
        law_reference = clause_data.get("law_reference", "")
        
        if not issue:
            return "Review and revise this clause for compliance."
        
        # Generate law-specific recommendations
        if law_reference:
            if "PDPA" in law_reference or "GDPR" in law_reference:
                return f"Revise to ensure data protection compliance with {law_reference}. " + \
                    "Consider adding explicit consent mechanisms and data retention limits."
            elif "EMPLOYMENT" in law_reference:
                return f"Update to comply with {law_reference} employment standards. " + \
                    "Ensure proper notice periods and compensation requirements."
            elif "CCPA" in law_reference:
                return f"Modify to meet {law_reference} consumer privacy requirements. " + \
                    "Add consumer rights provisions and opt-out mechanisms."
        
        # Generic recommendations based on severity
        if severity == "high":
            return "URGENT: This clause poses significant legal risk and must be revised immediately."
        elif severity == "medium":
            return "This clause should be reviewed and modified to reduce compliance risk."
        else:
            return "Consider revising this clause to improve compliance posture."

    def _calculate_comprehensive_risk_score(self, clause_flags: List[ClauseFlag], 
                                        compliance_feedback: List[ComplianceFeedback], 
                                        jurisdiction: str) -> ComplianceRiskScore:
        """
        Calculate comprehensive risk score using law-specific configurations.
        """
        try:
            # Base risk calculation
            financial_risk = 0
            operational_risk = 0
            reputation_risk = 0
            
            # Calculate financial risk from clause flags
            severity_multipliers = {"high": 3.0, "medium": 2.0, "low": 1.0}
            
            for clause in clause_flags:
                severity_multiplier = severity_multipliers.get(clause.severity, 1.0)
                law_ref = clause.law_reference
                
                # Get law-specific risk configuration
                if law_ref in self.risk_configurations:
                    risk_config = self.risk_configurations[law_ref]
                    base_amount = risk_config.get("base_risk_amount", 10000)
                    law_multiplier = risk_config.get("risk_multipliers", {}).get("base", 1.0)
                    financial_risk += base_amount * severity_multiplier * law_multiplier
                else:
                    # Default risk amounts by jurisdiction
                    jurisdiction_defaults = {
                        "EU": 50000,
                        "MY": 15000,
                        "SG": 25000,
                        "US": 35000
                    }
                    default_amount = jurisdiction_defaults.get(jurisdiction, 10000)
                    financial_risk += default_amount * severity_multiplier
            
            # Add compliance-based risk
            for feedback in compliance_feedback:
                missing_count = len(feedback.missing_requirements)
                law_ref = feedback.law_reference
                
                if law_ref in self.risk_configurations:
                    risk_config = self.risk_configurations[law_ref]
                    base_amount = risk_config.get("base_risk_amount", 5000)
                    compliance_multiplier = min(missing_count * 0.5, 2.0)  # Cap at 2x
                    financial_risk += base_amount * compliance_multiplier
                else:
                    financial_risk += missing_count * 5000  # Default per missing requirement
            
            # Calculate operational risk (0-100 scale)
            total_issues = len(clause_flags) + sum(len(f.missing_requirements) for f in compliance_feedback)
            operational_risk = min(total_issues * 15, 100)  # 15 points per issue, max 100
            
            # Calculate reputation risk based on law types
            reputation_sensitive_laws = ["PDPA", "GDPR", "CCPA", "EMPLOYMENT"]
            reputation_issues = 0
            
            for clause in clause_flags:
                if any(law in clause.law_reference for law in reputation_sensitive_laws):
                    reputation_issues += 2 if clause.severity == "high" else 1
            
            for feedback in compliance_feedback:
                if any(law in feedback.law_reference for law in reputation_sensitive_laws):
                    reputation_issues += len(feedback.missing_requirements)
            
            reputation_risk = min(reputation_issues * 12, 100)  # 12 points per issue, max 100
            
            # Determine overall risk level
            avg_risk = (operational_risk + reputation_risk) / 2
            if avg_risk >= 70 or financial_risk > 100000:
                risk_level = "high"
            elif avg_risk >= 40 or financial_risk > 50000:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            # Create detailed explanation
            risk_explanation = self._generate_risk_explanation(
                financial_risk, operational_risk, reputation_risk, 
                total_issues, jurisdiction
            )
            
            return ComplianceRiskScore(
                financial_risk=round(financial_risk, 2),
                operational_risk=round(operational_risk, 2),
                reputation_risk=round(reputation_risk, 2),
                overall_risk_level=risk_level,
                risk_explanation=risk_explanation
            )
            
        except Exception as e:
            logger.error(f"Risk calculation failed: {str(e)}")
            return ComplianceRiskScore(
                financial_risk=10000.0,
                operational_risk=50.0,
                reputation_risk=30.0,
                overall_risk_level="medium",
                risk_explanation="Risk calculation completed with default values due to analysis error."
            )

    def _generate_risk_explanation(self, financial_risk: float, operational_risk: float, 
                                reputation_risk: float, total_issues: int, jurisdiction: str) -> str:
        """
        Generate detailed risk explanation for stakeholders.
        """
        explanations = []
        
        # Financial risk explanation
        if financial_risk > 100000:
            explanations.append(f"High financial exposure (${financial_risk:,.0f}) due to significant compliance violations")
        elif financial_risk > 25000:
            explanations.append(f"Moderate financial risk (${financial_risk:,.0f}) from identified compliance gaps")
        else:
            explanations.append(f"Low financial risk (${financial_risk:,.0f}) with manageable compliance adjustments")
        
        # Operational risk explanation
        if operational_risk > 70:
            explanations.append(f"High operational risk ({operational_risk:.0f}/100) - immediate action required")
        elif operational_risk > 40:
            explanations.append(f"Moderate operational risk ({operational_risk:.0f}/100) - timely remediation needed")
        else:
            explanations.append(f"Low operational risk ({operational_risk:.0f}/100) - standard compliance monitoring")
        
        # Reputation risk explanation
        if reputation_risk > 60:
            explanations.append(f"Significant reputation risk ({reputation_risk:.0f}/100) from privacy/employment violations")
        elif reputation_risk > 30:
            explanations.append(f"Moderate reputation exposure ({reputation_risk:.0f}/100) requiring attention")
        else:
            explanations.append(f"Limited reputation risk ({reputation_risk:.0f}/100)")
        
        # Add jurisdiction-specific context
        jurisdiction_contexts = {
            "EU": "GDPR enforcement actions have resulted in substantial penalties",
            "MY": "Malaysian authorities actively monitor PDPA compliance",
            "SG": "Singapore maintains strict regulatory oversight",
            "US": "US state and federal enforcement varies by jurisdiction"
        }
        
        context = jurisdiction_contexts.get(jurisdiction, "Regulatory enforcement varies by jurisdiction")
        explanations.append(f"Jurisdiction context ({jurisdiction}): {context}")
        
        return ". ".join(explanations) + "."

    def _determine_overall_compliance_status(self, clause_flags: List[ClauseFlag], 
                                        compliance_feedback: List[ComplianceFeedback]) -> str:
        """
        Determine overall compliance status based on findings.
        """
        high_severity_clauses = [c for c in clause_flags if c.severity == "high"]
        non_compliant_laws = [f for f in compliance_feedback if f.compliance_status == "non_compliant"]
        
        if len(high_severity_clauses) > 2 or len(non_compliant_laws) > 3:
            return "non_compliant"
        elif len(high_severity_clauses) > 0 or len(non_compliant_laws) > 1:
            return "partially_compliant"
        elif len(clause_flags) > 0 or len(compliance_feedback) > 0:
            return "mostly_compliant"
        else:
            return "compliant"

    def _generate_actionable_recommendations(self, clause_flags: List[ClauseFlag], 
                                        compliance_feedback: List[ComplianceFeedback], 
                                        jurisdiction: str) -> List[str]:
        """
        Generate prioritized, actionable recommendations for contract improvement.
        """
        recommendations = []
        
        # Priority 1: High-severity clause issues
        high_priority_clauses = [c for c in clause_flags if c.severity == "high"]
        if high_priority_clauses:
            recommendations.append(
                f"IMMEDIATE ACTION: Address {len(high_priority_clauses)} high-risk clause(s) that pose significant legal exposure"
            )
        
        # Priority 2: Critical compliance gaps
        critical_compliance = [f for f in compliance_feedback if len(f.missing_requirements) > 2]
        if critical_compliance:
            laws = [f.law_reference for f in critical_compliance]
            recommendations.append(
                f"URGENT: Resolve major compliance gaps in {', '.join(laws)} within 30 days"
            )
        
        # Priority 3: Medium-severity issues
        medium_clauses = [c for c in clause_flags if c.severity == "medium"]
        if medium_clauses:
            recommendations.append(
                f"Review and revise {len(medium_clauses)} medium-risk clause(s) within 60 days"
            )
        
        # Priority 4: Remaining compliance issues
        remaining_compliance = [f for f in compliance_feedback if len(f.missing_requirements) <= 2 and f.missing_requirements]
        if remaining_compliance:
            recommendations.append(
                f"Address remaining compliance requirements across {len(remaining_compliance)} legal framework(s)"
            )
        
        # Priority 5: Preventive measures
        if clause_flags or compliance_feedback:
            recommendations.append(
                f"Implement regular contract review process for {jurisdiction} jurisdiction compliance"
            )
        
        # Add jurisdiction-specific recommendations
        jurisdiction_recommendations = {
            "EU": "Consider GDPR Article 28 data processing agreements for vendor relationships",
            "MY": "Ensure PDPA consent mechanisms meet Malaysian regulatory standards",
            "SG": "Align contract terms with Singapore's Personal Data Protection Act updates",
            "US": "Review state-specific requirements for applicable US jurisdictions"
        }
        
        if jurisdiction in jurisdiction_recommendations:
            recommendations.append(jurisdiction_recommendations[jurisdiction])
        
        # Legal review recommendation
        if len(clause_flags) > 3 or any(f.compliance_status == "non_compliant" for f in compliance_feedback):
            recommendations.append(
                "Engage qualified legal counsel for comprehensive contract revision and regulatory compliance verification"
            )
        
        return recommendations[:8]  # Limit to top 8 recommendations

    def _create_fallback_analysis_data(self, analysis_text: str, jurisdiction: str) -> Dict[str, Any]:
        """
        Create fallback analysis data when JSON parsing fails.
        """
        return {
            "summary": f"Contract analysis completed for {jurisdiction} jurisdiction. Limited analysis available due to parsing issues.",
            "flagged_clauses": [],
            "compliance_issues": [{
                "law": "GENERAL",
                "missing_requirements": ["Unable to perform detailed analysis"],
                "recommendations": ["Manual legal review recommended"],
                "risk_assessment": "Unknown risk - professional review needed"
            }]
        }

    def _create_empty_analysis_data(self, jurisdiction: str) -> Dict[str, Any]:
        """
        Create empty analysis data structure.
        """
        return {
            "summary": f"Contract analysis completed for {jurisdiction} jurisdiction. No significant issues identified.",
            "flagged_clauses": [],
            "compliance_issues": []
        }

    def _create_error_response(self, error_message: str, jurisdiction: str) -> ContractAnalysisResponse:
        """
        Create error response when analysis fails completely.
        """
        error_clause = ClauseFlag(
            clause_text="Analysis Error",
            issue_description=f"Contract analysis failed: {error_message}",
            severity="high",
            law_reference="SYSTEM",
            recommendation="Manual legal review required due to analysis system error"
        )
        
        error_feedback = ComplianceFeedback(
            law_reference="SYSTEM",
            missing_requirements=["Complete analysis unavailable"],
            recommendations=["Seek professional legal review"],
            risk_assessment="Unknown risk due to system error",
            compliance_status="unknown"
        )
        
        error_risk_score = ComplianceRiskScore(
            financial_risk=0.0,
            operational_risk=100.0,
            reputation_risk=50.0,
            overall_risk_level="high",
            risk_explanation="Analysis system error - professional review required for accurate risk assessment"
        )
        
        return ContractAnalysisResponse(
            summary=f"Contract analysis failed for {jurisdiction} jurisdiction. Professional legal review recommended.",
            clause_flags=[error_clause],
            compliance_feedback=[error_feedback],
            risk_score=error_risk_score,
            overall_compliance_status="unknown",
            actionable_recommendations=[
                "Seek immediate professional legal review",
                "Contact system administrators regarding analysis failure",
                "Use alternative compliance verification methods"
            ],
            jurisdiction_analyzed=jurisdiction,
            analysis_timestamp=self._get_current_timestamp()
        )

    def _get_current_timestamp(self) -> str:
        """
        Get current timestamp for analysis response.
        """
        from datetime import datetime
        return datetime.now().isoformat()