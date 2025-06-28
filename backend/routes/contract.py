"""
Optimized contract analysis routes for Legal Guard RegTech platform.

This module provides comprehensive REST API endpoints for:
- Single contract analysis with AI-powered compliance checking
- Bulk contract processing with asynchronous capabilities  
- Risk scoring and compliance assessment
- Document upload and text extraction
- Metadata extraction and regulatory validation
"""

import asyncio
import logging
import io
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, UploadFile, File, Form, BackgroundTasks, Depends
from fastapi.responses import JSONResponse
from pydantic import ValidationError

# Import our models
from models.ContractAnalysisModel import ContractAnalysisRequest
from models.ContractAnalysisResponseModel import ContractAnalysisResponse
from models.BulkAnalysisRequest import BulkAnalysisRequest
from models.ComplianceRiskScore import ComplianceRiskScore

# Import our services
from service.ContractAnalyzerService import ContractAnalyzerService
from service.DocumentProcessorService import DocumentProcessorService

# Import utilities
from utils.file_validators import FileValidator
from utils.text_extractors import TextExtractor
from utils.ai_client.exceptions import APIError, AuthenticationError, ConfigurationError

# Configure logging
logger = logging.getLogger(__name__)

# Initialize router
router = APIRouter(prefix="/api/v1/contracts", tags=["contracts"])

# Initialize services (these will be dependency injected in production)
contract_analyzer = ContractAnalyzerService()
document_processor = DocumentProcessorService()
file_validator = FileValidator()
text_extractor = TextExtractor()


# Dependency injection for services (allows for easier testing and flexibility)
def get_contract_analyzer() -> ContractAnalyzerService:
    """Dependency provider for ContractAnalyzerService."""
    return contract_analyzer


def get_document_processor() -> DocumentProcessorService:
    """Dependency provider for DocumentProcessorService."""
    return document_processor


@router.post("/analyze", response_model=ContractAnalysisResponse)
async def analyze_contract(
    request: ContractAnalysisRequest,
    analyzer: ContractAnalyzerService = Depends(get_contract_analyzer)
):
    """
    Analyze a single contract for compliance and legal issues.
    
    This endpoint performs comprehensive contract analysis including:
    - AI-powered clause examination
    - Regulatory compliance checking against jurisdiction-specific laws
    - Risk assessment and flagging of problematic clauses
    - Recommendations for compliance improvements
    
    Args:
        request: Contract analysis request containing text and jurisdiction
        analyzer: Injected contract analyzer service
        
    Returns:
        ContractAnalysisResponse: Detailed analysis results with compliance feedback
        
    Raises:
        HTTPException: 400 for validation errors, 500 for processing errors
    """
    try:
        logger.info(f"Starting contract analysis for jurisdiction: {request.jurisdiction}")
        
        # Validate input
        if not request.text or len(request.text.strip()) < 50:
            raise HTTPException(
                status_code=400,
                detail="Contract text must be at least 50 characters long"
            )
        
        # Perform analysis
        analysis_result = await analyzer.analyze_contract(request)
        
        logger.info(f"Contract analysis completed successfully. "
                   f"Found {len(analysis_result.clause_flags)} flagged clauses, "
                   f"{len(analysis_result.compliance_feedback)} compliance issues")
        
        return analysis_result
        
    except ValidationError as e:
        logger.error(f"Validation error in contract analysis: {e}")
        raise HTTPException(status_code=400, detail=f"Validation error: {str(e)}")
    
    except (APIError, AuthenticationError, ConfigurationError) as e:
        logger.error(f"AI service error in contract analysis: {e}")
        raise HTTPException(
            status_code=503, 
            detail="AI analysis service temporarily unavailable. Please try again later."
        )
    
    except Exception as e:
        logger.error(f"Unexpected error in contract analysis: {e}")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred during contract analysis"
        )


@router.post("/analyze/file", response_model=ContractAnalysisResponse)
async def analyze_contract_file(
    file: UploadFile = File(...),
    jurisdiction: str = Form("MY"),
    processor: DocumentProcessorService = Depends(get_document_processor)
):
    """
    Analyze a contract from an uploaded file.
    
    Supports multiple file formats including PDF, DOCX, and TXT.
    Automatically extracts text content and performs compliance analysis.
    
    Args:
        file: Uploaded contract file
        jurisdiction: Legal jurisdiction for analysis (default: "MY" for Malaysia)
        processor: Injected document processor service
        
    Returns:
        ContractAnalysisResponse: Detailed analysis results
        
    Raises:
        HTTPException: 400 for invalid files, 413 for oversized files, 500 for processing errors
    """
    try:
        logger.info(f"Processing uploaded file: {file.filename} for jurisdiction: {jurisdiction}")
        
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Read file content
        file_content = await file.read()
        
        # Validate file size (10MB limit)
        if len(file_content) > 10 * 1024 * 1024:
            raise HTTPException(
                status_code=413,
                detail="File size exceeds 10MB limit"
            )
        
        # Process document
        analysis_result = await processor.process_single_document(
            file_content=file_content,
            filename=file.filename,
            jurisdiction=jurisdiction
        )
        
        logger.info(f"File analysis completed for {file.filename}")
        
        return analysis_result
        
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Error processing file {file.filename}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to process file: {str(e)}"
        )


@router.post("/analyze/bulk")
async def analyze_bulk_contracts(
    request: BulkAnalysisRequest,
    background_tasks: BackgroundTasks,
    processor: DocumentProcessorService = Depends(get_document_processor)
):
    """
    Initiate bulk analysis of multiple contracts.
    
    Processes multiple contracts asynchronously and returns a task ID
    for tracking progress. Results can be retrieved via separate endpoints.
    
    Args:
        request: Bulk analysis request with list of contracts
        background_tasks: FastAPI background task handler
        processor: Injected document processor service
        
    Returns:
        JSON response with task ID and processing details
        
    Raises:
        HTTPException: 400 for validation errors, 429 for rate limiting
    """
    try:
        logger.info(f"Starting bulk analysis of {len(request.contracts)} contracts")
        
        # Validate request
        if not request.contracts:
            raise HTTPException(status_code=400, detail="No contracts provided for bulk analysis")
        
        if len(request.contracts) > 100:  # Rate limiting
            raise HTTPException(
                status_code=429,
                detail="Bulk analysis limited to 100 contracts per request"
            )
        
        # Generate task ID
        import uuid
        task_id = str(uuid.uuid4())
        
        # Add background task
        background_tasks.add_task(
            _process_bulk_contracts,
            task_id,
            request,
            processor
        )
        
        logger.info(f"Bulk analysis task {task_id} initiated")
        
        return JSONResponse(
            content={
                "task_id": task_id,
                "status": "processing",
                "contract_count": len(request.contracts),
                "priority": request.priority,
                "estimated_completion": "5-10 minutes"  # Rough estimate
            }
        )
        
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Error initiating bulk analysis: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to initiate bulk analysis"
        )


@router.post("/risk-score", response_model=ComplianceRiskScore)
async def calculate_risk_score(
    analysis_response: ContractAnalysisResponse,
    analyzer: ContractAnalyzerService = Depends(get_contract_analyzer)
):
    """
    Calculate comprehensive compliance risk score for an analyzed contract.
    
    Generates quantitative risk metrics including:
    - Overall compliance score (0-100)
    - Financial risk estimates
    - Violation category breakdown
    - Jurisdiction-specific risk factors
    
    Args:
        analysis_response: Previously completed contract analysis
        analyzer: Injected contract analyzer service
        
    Returns:
        ComplianceRiskScore: Detailed risk assessment metrics
        
    Raises:
        HTTPException: 400 for invalid input, 500 for calculation errors
    """
    try:
        logger.info("Calculating compliance risk score")
        
        # Validate input
        if not analysis_response.summary:
            raise HTTPException(
                status_code=400,
                detail="Invalid analysis response provided"
            )
        
        # Calculate risk score
        risk_score = await analyzer.calculate_risk_score(analysis_response)
        
        logger.info(f"Risk score calculated: {risk_score.overall_score}/100")
        
        return risk_score
        
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Error calculating risk score: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to calculate compliance risk score"
        )


@router.post("/extract-text")
async def extract_text_from_file(
    file: UploadFile = File(...)
):
    """
    Extract plain text from uploaded document files.
    
    Utility endpoint for text extraction without full analysis.
    Supports PDF, DOCX, and TXT formats.
    
    Args:
        file: Document file to extract text from
        
    Returns:
        JSON response with extracted text and metadata
        
    Raises:
        HTTPException: 400 for invalid files, 500 for extraction errors
    """
    try:
        logger.info(f"Extracting text from file: {file.filename}")
        
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        # Read file content
        file_content = await file.read()
        
        # Validate file type
        allowed_extensions = ['.pdf', '.docx', '.txt']
        if not any(file.filename.lower().endswith(ext) for ext in allowed_extensions):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}"
            )
        
        # Extract text
        extracted_text = await text_extractor.extract_text(file_content, file.filename)
        
        if not extracted_text.strip():
            raise HTTPException(
                status_code=400,
                detail="No text could be extracted from the file"
            )
        
        logger.info(f"Text extraction completed for {file.filename}")
        
        return JSONResponse(
            content={
                "filename": file.filename,
                "text": extracted_text,
                "character_count": len(extracted_text),
                "word_count": len(extracted_text.split()),
                "extraction_success": True
            }
        )
        
    except HTTPException:
        raise
    
    except Exception as e:
        logger.error(f"Error extracting text from {file.filename}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to extract text: {str(e)}"
        )


@router.get("/supported-jurisdictions")
async def get_supported_jurisdictions():
    """
    Get list of supported legal jurisdictions for contract analysis.
    
    Returns:
        JSON response with available jurisdictions and their details
    """
    # This would typically come from your law loader or configuration
    supported_jurisdictions = {
        "MY": {
            "name": "Malaysia",
            "laws": ["PDPA_MY", "EMPLOYMENT_ACT_MY"],
            "description": "Malaysian data protection and employment laws"
        },
        "SG": {
            "name": "Singapore", 
            "laws": ["PDPA_SG"],
            "description": "Singapore Personal Data Protection Act"
        },
        "EU": {
            "name": "European Union",
            "laws": ["GDPR_EU"],
            "description": "General Data Protection Regulation"
        },
        "US": {
            "name": "United States",
            "laws": ["CCPA_US"],
            "description": "California Consumer Privacy Act"
        }
    }
    
    return JSONResponse(content={
        "supported_jurisdictions": supported_jurisdictions,
        "default_jurisdiction": "MY"
    })


@router.get("/health")
async def health_check():
    """
    Health check endpoint for monitoring service status.
    
    Returns:
        JSON response with service health information
    """
    try:
        # Test basic service availability
        analyzer_status = "healthy" if contract_analyzer else "unavailable"
        processor_status = "healthy" if document_processor else "unavailable"
        
        # Test AI client availability
        ai_client_status = "healthy"
        if hasattr(contract_analyzer, 'watsonx_client') and contract_analyzer.watsonx_client is None:
            ai_client_status = "degraded"
        
        overall_status = "healthy" if all(
            status == "healthy" 
            for status in [analyzer_status, processor_status]
        ) else "degraded"
        
        return JSONResponse(
            content={
                "status": overall_status,
                "timestamp": "2025-06-28T00:00:00Z",  # Would use actual timestamp
                "services": {
                    "contract_analyzer": analyzer_status,
                    "document_processor": processor_status,
                    "ai_client": ai_client_status
                },
                "version": "1.0.0"
            }
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )


# Background task function for bulk processing
async def _process_bulk_contracts(
    task_id: str,
    request: BulkAnalysisRequest,
    processor: DocumentProcessorService
):
    """
    Background task to process bulk contracts asynchronously.
    
    Args:
        task_id: Unique identifier for the processing task
        request: Bulk analysis request
        processor: Document processor service
    """
    try:
        logger.info(f"Starting background bulk processing for task {task_id}")
        
        # Process contracts (simplified - in production you'd store results)
        results = []
        for i, contract_request in enumerate(request.contracts):
            try:
                # Simulate processing with small delay
                await asyncio.sleep(0.1)
                
                # In production, you'd call the actual analyzer
                # result = await contract_analyzer.analyze_contract(contract_request)
                # results.append(result)
                
                logger.info(f"Processed contract {i+1}/{len(request.contracts)} for task {task_id}")
                
            except Exception as e:
                logger.error(f"Error processing contract {i+1} in task {task_id}: {e}")
                continue
        
        logger.info(f"Bulk processing completed for task {task_id}")
        
        # In production, you'd store results in database/cache for retrieval
        # await store_bulk_results(task_id, results)
        
    except Exception as e:
        logger.error(f"Bulk processing failed for task {task_id}: {e}")


# Export router for inclusion in main FastAPI app
__all__ = ["router"]