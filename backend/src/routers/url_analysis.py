from fastapi import APIRouter, HTTPException
from models import URLAnalysisRequest, URLAnalysisResponse, ThreatType
from services import VirusTotalService, PageScannerService
from config import logger

router = APIRouter(
    tags=["URL Analysis"],
    prefix="/url-analysis"
)

vt_service = VirusTotalService()

@router.post("/analyze-url", response_model=URLAnalysisResponse)
async def analyze_url(request: URLAnalysisRequest):
    """Lightweight URL analysis - returns only essential data"""
    
    try:
        url_str = str(request.url)
        logger.info(f"Backend analyzing: {url_str} (client confidence: {request.confidence})")
        
        # Get VirusTotal analysis
        vt_result = await vt_service.analyze_url(url_str)
        
        # Create detailed, user-friendly explanations
        if vt_result.get("available") and vt_result.get("is_suspicious"):
            # Server found threat via VirusTotal
            malicious = vt_result.get("malicious", 0)
            total = vt_result.get("total", 0)
            
            if malicious > 0:
                reason = f"🛡️ Server Alert: {malicious} security vendors flagged this URL as malicious"
                threat_type = ThreatType.MALWARE
            else:
                reason = f"🛡️ Server Alert: Multiple security vendors flagged this URL as suspicious"
                threat_type = ThreatType.SUSPICIOUS
            
            return URLAnalysisResponse(
                suspicious=True,
                confidence=min(0.95, vt_result.get("confidence", 0.8)),
                reason=reason,
                type=threat_type
            )
            
        elif vt_result.get("available") and not vt_result.get("is_suspicious"):
            # VirusTotal says it's clean
            total = vt_result.get("total", 0)
            return URLAnalysisResponse(
                suspicious=False,
                confidence=0.9,  # High confidence when VirusTotal confirms clean
                reason=f"🛡️ Server Verified: Clean scan by {total} security vendors",
                type=ThreatType.SAFE
            )
            
        elif request.confidence > 0.6:
            # Trust client analysis but enhance the explanation
            threat_type = ThreatType.TYPO if request.reason == "typo_detected" else ThreatType.SUSPICIOUS
            
            # Decode and enhance client reasons
            enhanced_reason = _enhance_client_reason(request.reason, url_str)
            
            return URLAnalysisResponse(
                suspicious=True,
                confidence=min(0.9, request.confidence + 0.1),  # Slight server boost
                reason=f"🛡️ Server Confirmed: {enhanced_reason}",
                type=threat_type
            )
        else:
            # No clear threat detected
            return URLAnalysisResponse(
                suspicious=False,
                confidence=0.2,
                reason="🛡️ Server Analysis: No immediate threats detected, but exercise caution",
                type=ThreatType.SAFE
            )
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        # Fallback with server error indication
        return URLAnalysisResponse(
            suspicious=request.confidence > 0.6,
            confidence=request.confidence,
            reason=f"⚠️ Server Error: Using local analysis - {_enhance_client_reason(request.reason, str(request.url))}",
            type=ThreatType.SUSPICIOUS if request.confidence > 0.6 else ThreatType.SAFE
        )
    


def _enhance_client_reason(encoded_reason: str, url: str) -> str:
    """Convert encoded reasons to user-friendly explanations"""
    
    reason_explanations = {
        'ip_addr': 'Domain uses IP address instead of proper domain name (common phishing technique)',
        'bad_tld': 'Domain uses suspicious top-level domain frequently abused by scammers',
        'sus_keywords': 'URL contains keywords commonly used in phishing attacks',
        'typo_detected': f'Domain appears to impersonate a legitimate website through typosquatting',
        'bad_subdomain': 'Domain uses suspicious subdomain patterns often seen in scams',
        'other': 'Domain exhibits suspicious characteristics detected by security analysis'
    }
    
    enhanced = reason_explanations.get(encoded_reason, reason_explanations['other'])
    
    # Add Singapore-specific context if relevant
    if any(sg_term in url.lower() for sg_term in ['singpass', 'cpf', 'iras', 'dbs', 'ocbc', 'uob', 'singapore']):
        enhanced += " (⚠️ Targets Singapore users - report to ScamShield)"
    
    return enhanced

@router.post("/scan-page", response_model=dict)
async def scan_page_comprehensive(request: dict):
    """
    Comprehensive page scanning endpoint - Returns only client-needed data
    """
    try:
        page_url = request.get("page_url")
        extracted_links = request.get("extracted_links", [])
        
        if not page_url:
            raise HTTPException(status_code=400, detail="page_url is required")
        
        logger.info(f"🔍 Comprehensive scan request for: {page_url}")
        logger.info(f"🔗 Extracted links count: {len(extracted_links)}")
        logger.info(f"🔗 Extracted links: {extracted_links[:5]}")  # Log first 5 links
        
        scanner = PageScannerService()
        results = await scanner.scan_page_comprehensive(page_url, extracted_links)
        
        logger.info(f"📊 Scan results: {results}")
        
        # Return only what the client needs
        response_data = {
            "success": True,
            "is_suspicious": results["overall_risk"] in ["medium", "high"],
            "confidence": 0.8 if results["overall_risk"] == "high" else 0.6 if results["overall_risk"] == "medium" else 0.3,
            "reason": _generate_user_friendly_reason(results),
            "links_scanned": results["links_analyzed"],
            "suspicious_links_found": len(results["suspicious_links"]),
            "suspicious_links": [
                {
                    "url": link["url"],
                    "reason": link["reason"]
                }
                for link in results["suspicious_links"][:5]  # Limit to 5 for UI
            ],
            "scan_summary": _generate_scan_summary(results)
        }
        
        logger.info(f"📤 Sending response: {response_data}")
        return response_data
        
    except Exception as e:
        logger.error(f"💥 Page scan failed: {str(e)}")
        return {
            "success": False,
            "is_suspicious": False,
            "confidence": 0.0,
            "reason": "Scan failed - please try again",
            "links_scanned": 0,
            "suspicious_links_found": 0,
            "suspicious_links": [],
            "scan_summary": "Unable to complete scan"
        }

def _generate_user_friendly_reason(results):
    """Generate simple, user-friendly explanations"""
    if results["overall_risk"] == "high":
        return f"🚨 High risk detected - found {len(results['suspicious_links'])} suspicious links"
    elif results["overall_risk"] == "medium":
        return f"⚠️ Some concerns found - {len(results['suspicious_links'])} potentially suspicious links detected"
    else:
        return f"✅ Scan complete - checked {results['links_analyzed']} links, no major threats found"

def _generate_scan_summary(results):
    """Generate a brief summary for display"""
    return f"Scanned {results['links_analyzed']} links, found {len(results['suspicious_links'])} suspicious"
