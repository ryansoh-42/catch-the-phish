import vt
import asyncio
from typing import Dict
from config import logger, VIRUS_TOTAL_API_KEY

class VirusTotalService:
    def __init__(self):
        self.api_key = VIRUS_TOTAL_API_KEY
        
    async def analyze_url(self, url: str) -> Dict:
        """Analyze URL using VirusTotal API v3 with official client"""
        if not self.api_key:
            logger.warning("VirusTotal API key not configured")
            return {
                "available": False,
                "reason": "VirusTotal API key not configured",
                "confidence": 0.0,
                "is_suspicious": False
            }
        
        try:
            # Create client without async context manager to avoid event loop conflicts
            client = vt.Client(self.api_key)
            
            try:
                # Use the official vt.url_id() function
                url_id = vt.url_id(url)
                
                try:
                    # Try to get existing URL object
                    url_obj = await client.get_object_async(f"/urls/{url_id}")
                    logger.info(f"Found existing VirusTotal analysis for: {url}")
                    return self._parse_url_object(url_obj, url)
                    
                except vt.APIError as e:
                    if e.code == "NotFoundError":
                        # URL not found, submit for scanning
                        logger.info(f"URL not found in VirusTotal, submitting for scan: {url}")
                        
                        # Submit URL for scanning
                        analysis = await client.scan_url_async(url)
                        
                        # Wait a bit and try to get the result
                        await asyncio.sleep(5)  # Give it more time to process
                        
                        try:
                            # Try to get the analysis result
                            url_obj = await client.get_object_async(f"/urls/{url_id}")
                            return self._parse_url_object(url_obj, url)
                        except vt.APIError:
                            # Analysis still in progress
                            return {
                                "available": True,
                                "is_suspicious": False,
                                "confidence": 0.1,
                                "reason": "URL submitted to VirusTotal for analysis (results pending)",
                                "scan_submitted": True,
                                "analysis_id": analysis.id
                            }
                    else:
                        # Handle other API errors
                        logger.error(f"VirusTotal API error: {e.code} - {e.message}")
                        return {
                            "available": False,
                            "reason": f"VirusTotal API error: {e.message}",
                            "confidence": 0.0,
                            "is_suspicious": False
                        }
                        
            finally:
                # Always close the client
                await client.close_async()
                
        except Exception as e:
            logger.error(f"VirusTotal unexpected error: {e}")
            return {
                "available": False,
                "reason": f"VirusTotal error: {str(e)}",
                "confidence": 0.0,
                "is_suspicious": False
            }
    
    def _parse_url_object(self, url_obj, original_url: str) -> Dict:
        """Parse VirusTotal URL object into our format"""
        try:
            # Check if analysis exists
            if not hasattr(url_obj, 'last_analysis_stats'):
                return {
                    "available": False,
                    "reason": "No analysis stats available",
                    "confidence": 0.0,
                    "is_suspicious": False
                }
            
            # Get analysis stats - correct way to access
            stats = url_obj.last_analysis_stats
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0) 
            undetected = stats.get("undetected", 0)
            harmless = stats.get("harmless", 0)
            
            total = malicious + suspicious + undetected + harmless
            
            if total == 0:
                return {
                    "available": False,
                    "reason": "No VirusTotal analysis available",
                    "confidence": 0.0,
                    "is_suspicious": False
                }
            
            # Calculate threat level
            threat_count = malicious + suspicious
            is_suspicious = threat_count > 0
            
            # Calculate confidence based on detection ratio
            if total > 0:
                threat_ratio = threat_count / total
                # More conservative confidence calculation
                if threat_count == 0:
                    confidence = 0.1
                elif threat_ratio < 0.1:
                    confidence = 0.3
                elif threat_ratio < 0.3:
                    confidence = 0.6
                else:
                    confidence = min(0.95, 0.7 + (threat_ratio * 0.25))
            else:
                confidence = 0.1
            
            # Get scan date
            scan_date = "Unknown"
            if hasattr(url_obj, 'last_analysis_date'):
                scan_date = str(url_obj.last_analysis_date)
            
            # Get detected engines (up to 5)
            detected_engines = []
            if hasattr(url_obj, 'last_analysis_results'):
                for engine, result in url_obj.last_analysis_results.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        detected_engines.append(engine)
                        if len(detected_engines) >= 5:
                            break
            
            # Create reason message
            reason = (
                f"VirusTotal: {threat_count}/{total} engines flagged this URL "
                f"({malicious} malicious, {suspicious} suspicious)"
                if is_suspicious 
                else f"VirusTotal: Clean scan ({total} engines checked)"
            )
            
            # Generate permalink using the correct URL ID
            url_id = vt.url_id(original_url)
            permalink = f"https://www.virustotal.com/gui/url/{url_id}"
            
            return {
                "available": True,
                "is_suspicious": is_suspicious,
                "confidence": confidence,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "undetected": undetected,
                "total": total,
                "scan_date": scan_date,
                "detected_engines": detected_engines,
                "reason": reason,
                "permalink": permalink
            }
            
        except Exception as e:
            logger.error(f"Error parsing VirusTotal response: {e}")
            return {
                "available": False,
                "reason": f"Error parsing VirusTotal response: {str(e)}",
                "confidence": 0.0,
                "is_suspicious": False
            }
