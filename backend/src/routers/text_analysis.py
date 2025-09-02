from fastapi import APIRouter, HTTPException
from models import TextAnalysisRequest, TextChunkRequest, TextAnalysisResponse, PageTextAnalysisResponse
from services import TextAnalyzerService
from config import logger

router = APIRouter(
    tags=["Text Analysis"],
    prefix="/text-analysis"
)

text_analyzer = TextAnalyzerService()

@router.post("/analyze-text", response_model=TextAnalysisResponse)
async def analyze_text(request: TextAnalysisRequest):
    """Analyze single text for phishing content"""
    try:
        result = await text_analyzer.analyze_single_text(request.text)
        return TextAnalysisResponse(**result)
    except Exception as e:
        logger.error(f"Text analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-page-text", response_model=PageTextAnalysisResponse)
async def analyze_page_text(request: TextChunkRequest):
    """Analyze webpage text chunks"""
    try:
        result = await text_analyzer.analyze_page_chunks(request.chunks)
        return PageTextAnalysisResponse(**result)
    except Exception as e:
        logger.error(f"Page analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
