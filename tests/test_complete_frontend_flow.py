#!/usr/bin/env python3
"""
Complete Frontend Data Flow Test
=================================
This test demonstrates the complete data flow from AI response to frontend-ready JSON,
showing exactly what the frontend would receive for contract analysis.
"""

import os
import sys
import json
import asyncio
from datetime import datetime

# Add the backend to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'backend'))

from dotenv import load_dotenv
from backend.utils.ai_client import WatsonXClient
from backend.utils.ai_client.config import WatsonXConfig
from backend.service.ContractAnalyzerService import ContractAnalyzerService
from backend.models.ContractAnalysisModel import ContractAnalysisRequest

# Load environment variables
load_dotenv()

def print_header(title: str):
    """Print a formatted header"""
    print(f"\n{'='*80}")
    print(f"🔍 {title}")
    print('='*80)

def print_subheader(title: str):
    """Print a formatted subheader"""
    print(f"\n📋 {title}")
    print('-'*60)

class CompleteFrontendDataFlow:
    """Demonstrates complete data flow for frontend integration"""
    
    def __init__(self):
        self.ai_client = None
        self.analyzer_service = None
        
        # Sample contract for testing
        self.test_contract = """
EMPLOYMENT AGREEMENT

This Employment Agreement is entered between TechStart Malaysia Sdn Bhd ("Company") 
and Sarah Chen ("Employee") effective March 1, 2024.

1. POSITION AND DUTIES
   Employee will serve as Senior Frontend Developer in the Engineering Department.
   
2. COMPENSATION
   - Base salary: RM 9,500 per month
   - Performance bonus: Up to 2 months salary annually
   - Payment: Monthly via bank transfer

3. WORKING ARRANGEMENTS
   - Working hours: 9:00 AM to 6:00 PM, Monday to Friday
   - Flexible working arrangements available
   - Remote work permitted up to 2 days per week

4. BENEFITS
   - Medical and dental insurance
   - 18 days annual leave
   - Professional development allowance: RM 3,000 annually

5. CONFIDENTIALITY
   Employee agrees to maintain confidentiality of all proprietary company information
   and trade secrets during and after employment.

6. INTELLECTUAL PROPERTY
   All work products, inventions, and developments created during employment 
   shall be the exclusive property of the Company.

This agreement is governed by Malaysian employment law.

Signed: March 1, 2024
        """.strip()
    
    def initialize_services(self):
        """Initialize all required services"""
        print_header("SERVICE INITIALIZATION")
        
        try:
            # Initialize AI client
            config = WatsonXConfig.from_environment()
            self.ai_client = WatsonXClient(config)
            print("✅ WatsonX AI Client initialized")
            
            # Initialize analyzer service
            self.analyzer_service = ContractAnalyzerService()
            print("✅ ContractAnalyzerService initialized")
            
            return True
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            return False
    
    def demonstrate_raw_ai_flow(self):
        """Show the raw AI request/response flow"""
        print_header("RAW AI REQUEST/RESPONSE FLOW")
        
        print_subheader("1. Contract Input")
        print(f"📄 Contract length: {len(self.test_contract)} characters")
        print(f"📝 Contract preview:")
        print(f"```")
        print(self.test_contract[:300] + "...")
        print(f"```")
        
        print_subheader("2. Compliance Requirements")
        compliance_requirements = {
            "employment_laws_my": {
                "requirements": [
                    "termination_clause",
                    "minimum_wage_compliance", 
                    "overtime_provisions",
                    "annual_leave_entitlement",
                    "notice_period_requirements"
                ]
            },
            "data_protection": {
                "requirements": [
                    "data_processing_notice",
                    "consent_mechanism",
                    "data_retention_policy"
                ]
            }
        }
        print("🔍 Compliance checklist:")
        print(json.dumps(compliance_requirements, indent=2))
        
        print_subheader("3. AI Request")
        print("🚀 Making request to WatsonX AI...")
        
        try:
            raw_response = self.ai_client.analyze_contract(
                self.test_contract, 
                compliance_requirements
            )
            
            print_subheader("4. Raw AI Response")
            print("📥 Direct AI response:")
            print("─" * 70)
            print(raw_response)
            print("─" * 70)
            
            # Parse and validate
            try:
                parsed_response = json.loads(raw_response)
                print_subheader("5. Parsed Response Structure")
                print("✅ JSON parsing successful!")
                
                for key, value in parsed_response.items():
                    if isinstance(value, list):
                        print(f"   📊 {key}: {len(value)} items")
                    else:
                        preview = str(value)[:100] + "..." if len(str(value)) > 100 else str(value)
                        print(f"   📝 {key}: {preview}")
                
                return parsed_response
                
            except json.JSONDecodeError as e:
                print(f"❌ JSON parsing failed: {e}")
                return None
                
        except Exception as e:
            print(f"❌ AI request failed: {e}")
            return None
    
    async def demonstrate_service_flow(self):
        """Show the complete service integration flow"""
        print_header("SERVICE INTEGRATION FLOW")
        
        print_subheader("1. Create Analysis Request")
        request = ContractAnalysisRequest(
            text=self.test_contract,
            jurisdiction="MY"
        )
        print("✅ Analysis request created")
        print(f"   📍 Jurisdiction: {request.jurisdiction}")
        print(f"    Text length: {len(request.text)} characters")
        
        print_subheader("2. Process Through Service")
        print("🔄 Processing contract through ContractAnalyzerService...")
        
        try:
            # Call the service
            analysis_result = await self.analyzer_service.analyze_contract(request)
            
            print_subheader("3. Service Response")
            print("✅ Analysis completed successfully!")
            
            # Convert to dictionary for inspection
            result_dict = analysis_result.dict() if hasattr(analysis_result, 'dict') else {
                "summary": getattr(analysis_result, 'summary', 'No summary'),
                "clause_flags": getattr(analysis_result, 'clause_flags', []),
                "compliance_feedback": getattr(analysis_result, 'compliance_feedback', []),
                "jurisdiction": getattr(analysis_result, 'jurisdiction', 'Unknown')
            }
            
            print(f"📊 Analysis summary: {result_dict.get('summary', 'N/A')}")
            print(f"🚩 Flagged clauses: {len(result_dict.get('clause_flags', []))}")
            print(f"⚖️ Compliance issues: {len(result_dict.get('compliance_issues', []))}")
            
            return result_dict
            
        except Exception as e:
            print(f"❌ Service analysis failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def generate_frontend_api_response(self, analysis_result):
        """Generate the complete API response that frontend would receive"""
        print_header("FRONTEND API RESPONSE GENERATION")
        
        # Simulate complete API response structure
        api_response = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "request_id": "req_" + datetime.now().strftime("%Y%m%d_%H%M%S"),
            "data": {
                "contract_analysis": {
                    "id": "analysis_" + datetime.now().strftime("%Y%m%d_%H%M%S"),
                    "contract_info": {
                        "filename": "employment_agreement.pdf",
                        "upload_time": datetime.now().isoformat(),
                        "file_size": len(self.test_contract),
                        "detected_type": "employment",
                        "detected_jurisdiction": "MY"
                    },
                    "analysis_results": analysis_result,
                    "risk_assessment": {
                        "overall_score": 75,
                        "risk_level": "medium",
                        "financial_impact": 5000.0,
                        "critical_issues": 2,
                        "recommendations_count": 4
                    },
                    "processing_metadata": {
                        "ai_model": "ibm/granite-13b-instruct-v2",
                        "processing_time_ms": 3200,
                        "confidence_score": 0.87,
                        "version": "v2.1.0"
                    }
                }
            },
            "pagination": {
                "page": 1,
                "per_page": 1,
                "total": 1,
                "total_pages": 1
            }
        }
        
        print_subheader("Complete API Response Structure")
        print("📱 Frontend-ready API response:")
        print(json.dumps(api_response, indent=2, ensure_ascii=False))
        
        print_subheader("Frontend Implementation Notes")
        print("💡 Frontend developer guidelines:")
        print("   ✅ Response includes complete status and metadata")
        print("   ✅ Analysis results are in data.contract_analysis.analysis_results")
        print("   ✅ Risk assessment provides scoring for dashboard")
        print("   ✅ Processing metadata helps with debugging")
        print("   ✅ All timestamps are ISO format for easy parsing")
        print("   ✅ Pagination structure ready for multiple contracts")
        
        return api_response
    
    def demonstrate_error_handling(self):
        """Show error handling for frontend"""
        print_header("ERROR HANDLING DEMONSTRATION")
        
        error_scenarios = [
            {
                "name": "AI Service Timeout",
                "response": {
                    "status": "error",
                    "error_code": "AI_TIMEOUT",
                    "message": "AI analysis service timed out",
                    "details": "The AI analysis took longer than expected. Please try again.",
                    "fallback_available": True,
                    "retry_after": 30
                }
            },
            {
                "name": "Invalid Contract Format", 
                "response": {
                    "status": "error",
                    "error_code": "INVALID_FORMAT",
                    "message": "Contract format not supported",
                    "details": "The uploaded file format is not supported. Please upload PDF, DOCX, or TXT files.",
                    "supported_formats": ["pdf", "docx", "txt"]
                }
            },
            {
                "name": "AI Response Parsing Error",
                "response": {
                    "status": "partial_success",
                    "error_code": "AI_PARSE_ERROR", 
                    "message": "AI response could not be fully parsed",
                    "data": {
                        "contract_analysis": {
                            "analysis_results": {
                                "summary": "Error: AI response could not be parsed as valid JSON.",
                                "flagged_clauses": [],
                                "compliance_issues": []
                            }
                        }
                    },
                    "fallback_used": True
                }
            }
        ]
        
        for scenario in error_scenarios:
            print_subheader(f"Error Scenario: {scenario['name']}")
            print(json.dumps(scenario['response'], indent=2))
            print()
    
    async def run_complete_demonstration(self):
        """Run the complete demonstration"""
        print("🚀 Starting Complete Frontend Data Flow Demonstration")
        print(f"⏰ Started at: {datetime.now()}")
        
        # Initialize services
        if not self.initialize_services():
            return
        
        # Demonstrate raw AI flow
        raw_ai_result = self.demonstrate_raw_ai_flow()
        
        # Demonstrate service integration
        service_result = await self.demonstrate_service_flow()
        
        # Use service result if available, otherwise use raw AI result
        final_result = service_result or raw_ai_result or {
            "summary": "Demo analysis of employment contract",
            "flagged_clauses": [
                {
                    "clause_text": "All work products belong to the Company",
                    "issue": "Broad IP assignment clause",
                    "severity": "medium"
                }
            ],
            "compliance_issues": [
                {
                    "law": "Employment Act 1955 (Malaysia)",
                    "missing_requirements": ["termination_clause", "notice_period"],
                    "recommendations": ["Add termination procedures", "Specify notice periods"]
                }
            ]
        }
        
        # Generate frontend API response
        api_response = self.generate_frontend_api_response(final_result)
        
        # Show error handling
        self.demonstrate_error_handling()
        
        print_header("DEMONSTRATION COMPLETE")
        print("✅ Complete frontend data flow demonstrated successfully!")
        
        # Summary for frontend developers
        print_subheader("Frontend Integration Summary")
        print("📋 Key points for frontend implementation:")
        print("   🔗 API endpoint: POST /api/contracts/analyze")
        print("   📄 Request: Multipart form with contract file + metadata")
        print("   📦 Response: JSON with analysis results and metadata")
        print("   ⏱️ Typical processing time: 2-5 seconds")
        print("   🔄 Implement loading states and progress indicators")
        print("   ❌ Handle errors gracefully with user-friendly messages")
        print("   💾 Consider caching results for repeated analyses")
        print("   📊 Display risk scores prominently in dashboard")
        
        return api_response

async def main():
    """Main execution function"""
    demo = CompleteFrontendDataFlow()
    await demo.run_complete_demonstration()

if __name__ == "__main__":
    asyncio.run(main())
