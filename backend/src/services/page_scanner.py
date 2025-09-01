import vt
import asyncio
from typing import Dict, List
from urllib.parse import urljoin, urlparse
from config import logger
from .virustotal import VirusTotalService

class PageScannerService:
    def __init__(self):
        self.vt_service = VirusTotalService()
    
    async def scan_page_comprehensive(self, page_url: str, extracted_links: List[str] = None) -> Dict:
        """
        Comprehensive page scanning combining:
        1. Main page URL scan (VirusTotal)
        2. Extracted links analysis (your local + VirusTotal)
        3. Domain reputation check
        """
        results = {
            "page_url": page_url,
            "page_analysis": None,
            "links_analyzed": 0,
            "suspicious_links": [],
            "clean_links": [],
            "overall_risk": "low",
            "recommendations": []
        }
        
        try:
            # 1. Scan main page URL with VirusTotal
            logger.info(f"Scanning main page: {page_url}")
            page_analysis = await self.vt_service.analyze_url(page_url)
            results["page_analysis"] = page_analysis
            
            # 2. Analyze extracted links (if provided)
            if extracted_links:
                logger.info(f"Analyzing {len(extracted_links)} extracted links")
                
                for link in extracted_links[:10]:  # Limit to 10 links to avoid API limits
                    try:
                        link_analysis = await self.vt_service.analyze_url(link)
                        results["links_analyzed"] += 1
                        
                        if link_analysis.get("is_suspicious", False):
                            results["suspicious_links"].append({
                                "url": link,
                                "reason": link_analysis.get("reason", "Flagged by security vendors"),
                                "confidence": link_analysis.get("confidence", 0.5)
                            })
                        else:
                            results["clean_links"].append(link)
                            
                        # Small delay to respect API limits
                        await asyncio.sleep(1)
                        
                    except Exception as e:
                        logger.warning(f"Error analyzing link {link}: {str(e)}")
            
            # 3. Determine overall risk
            risk_factors = 0
            
            if page_analysis.get("is_suspicious", False):
                risk_factors += 3
                results["recommendations"].append("⚠️ Main page flagged by security vendors")
            
            if len(results["suspicious_links"]) > 0:
                risk_factors += len(results["suspicious_links"])
                results["recommendations"].append(f"🔗 Found {len(results['suspicious_links'])} suspicious links")
            
            if len(results["suspicious_links"]) > 2:
                risk_factors += 2
                results["recommendations"].append("🚨 Multiple suspicious links detected - high risk")
            
            # Calculate overall risk
            if risk_factors >= 5:
                results["overall_risk"] = "high"
            elif risk_factors >= 2:
                results["overall_risk"] = "medium"
            else:
                results["overall_risk"] = "low"
                results["recommendations"].append("✅ No major threats detected")
            
            return results
            
        except Exception as e:
            logger.error(f"Error in comprehensive page scan: {str(e)}")
            return {
                **results,
                "error": str(e),
                "overall_risk": "unknown"
            }
