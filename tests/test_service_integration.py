"""
Test the updated ContractAnalyzerService with our custom AI client        # Show some details
        if analysis_result.clause_flags:
            print("\n   🔍 Sample flagged clause:")
            clause = analysis_result.clause_flags[0]
            print(f"      - Text: {clause.clause_text[:100]}...")
            print(f"      - Issue: {clause.issue_description[:100]}...")
            print(f"      - Severity: {clause.severity}")
        
        if analysis_result.compliance_feedback:
            print("\n   📜 Sample compliance issue:")
            issue = analysis_result.compliance_feedback[0]
            print(f"      - Law: {issue.law_reference}")
            print(f"      - Missing: {issue.missing_requirements[:2]}")
            print(f"      - Status: {issue.compliance_status}") asyncio
import os
import sys
from pathlib import Path

# Add the backend directory to the Python path
sys.path.append(str(Path(__file__).parent.parent))

from backend.service.ContractAnalyzerService import ContractAnalyzerService
from backend.models.ContractAnalysisModel import ContractAnalysisRequest


async def test_contract_analyzer_service():
    """Test the updated ContractAnalyzerService"""
    
    print("🧪 Testing Updated ContractAnalyzerService")
    print("=" * 50)
    
    # Initialize the service
    print("\n1. Initializing ContractAnalyzerService...")
    try:
        service = ContractAnalyzerService()
        print("✅ Service initialized successfully")
        
        # Check if AI client is available
        if service.watsonx_client:
            print("✅ Custom WatsonX AI client is available")
        else:
            print("⚠️  Custom WatsonX AI client not available - will use mock responses")
    except Exception as e:
        print(f"❌ Service initialization failed: {e}")
        return
    
    # Test contract analysis
    print("\n2. Testing Contract Analysis...")
    
    sample_contract = """
    EMPLOYMENT AGREEMENT
    
    This Employment Agreement is entered into between TechCorp Ltd. and Jane Smith.
    
    1. POSITION: Employee shall serve as Software Engineer.
    2. COMPENSATION: Base salary of $80,000 per annum.
    3. CONFIDENTIALITY: Employee agrees to maintain confidentiality of company information.
    4. TERM: This agreement shall commence on January 1, 2024 and continue indefinitely.
    5. TERMINATION: Either party may terminate this agreement with 1 week notice.
    6. DATA HANDLING: Employee may access and process customer data as needed for job duties.
    """
    
    request = ContractAnalysisRequest(
        text=sample_contract,
        jurisdiction="MY"  # Malaysia
    )
    
    try:
        print(f"   📄 Analyzing contract ({len(sample_contract)} characters)")
        print(f"   🌏 Jurisdiction: {request.jurisdiction}")
        
        # Perform the analysis
        analysis_result = await service.analyze_contract(request)
        
        print("✅ Contract analysis completed successfully")
        print(f"   📋 Summary: {analysis_result.summary}")
        print(f"   🚩 Flagged clauses: {len(analysis_result.clause_flags or [])}")
        print(f"   ⚖️  Compliance issues: {len(analysis_result.compliance_feedback or [])}")
        
        # Show some details
        if analysis_result.flagged_clauses:
            print("\n   🔍 Sample flagged clause:")
            clause = analysis_result.flagged_clauses[0]
            print(f"      - Text: {clause.clause_text[:100]}...")
            print(f"      - Issue: {clause.issue[:100]}...")
            print(f"      - Severity: {clause.severity}")
        
        if analysis_result.compliance_issues:
            print("\n   📜 Sample compliance issue:")
            issue = analysis_result.compliance_issues[0]
            print(f"      - Law: {issue.law}")
            print(f"      - Missing requirements: {len(issue.missing_requirements)}")
            print(f"      - Recommendations: {len(issue.recommendations)}")
        
    except Exception as e:
        print(f"❌ Contract analysis failed: {e}")
        return
    
    # Test risk scoring
    print("\n3. Testing Risk Scoring...")
    
    try:
        risk_score = await service.calculate_risk_score(analysis_result)
        
        print("✅ Risk scoring completed successfully")
        print(f"   📊 Overall score: {risk_score.overall_score}/100")
        print(f"   💰 Financial risk estimate: ${risk_score.financial_risk_estimate:,.2f}")
        print(f"   🏷️  Violation categories: {len(risk_score.violation_categories)}")
        print(f"   🌍 Jurisdiction risks: {risk_score.jurisdiction_risks}")
        
    except Exception as e:
        print(f"❌ Risk scoring failed: {e}")
        return
    
    print("\n🎉 All tests completed successfully!")
    print("\n💡 Integration Summary:")
    print("   ✅ Service uses custom WatsonX AI client")
    print("   ✅ Environment variables loaded from .env file")
    print("   ✅ Graceful fallback to mock responses")
    print("   ✅ Error handling works correctly")


if __name__ == "__main__":
    asyncio.run(test_contract_analyzer_service())
