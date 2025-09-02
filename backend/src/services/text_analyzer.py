import aiohttp
import asyncio
import time
from typing import Dict, List, Optional
from config import logger, HUGGINGFACE_API_KEY

class TextAnalyzerService:
    def __init__(self):
        self.api_key = HUGGINGFACE_API_KEY
        
        # Tested and working phishing detection models
        self.models = [
            {
                'name': 'phishing_specialized',
                'url': 'https://api-inference.huggingface.co/models/ealvaradob/bert-finetuned-phishing',
                'description': 'BERT fine-tuned specifically for phishing detection',
                'threshold': 0.5,
                'model_type': 'phishing_classifier'
            },
            {
                'name': 'toxic_roberta',
                'url': 'https://api-inference.huggingface.co/models/unitary/toxic-bert',
                'description': 'Reliable toxic content detection (good for scams)',
                'threshold': 0.6,
                'model_type': 'toxic_classifier'
            },
            {
                'name': 'spam_detector',
                'url': 'https://api-inference.huggingface.co/models/mrm8488/bert-tiny-finetuned-sms-spam-detection',
                'description': 'BERT fine-tuned for spam detection',
                'threshold': 0.5,
                'model_type': 'spam_classifier'
            }
        ]
    
    async def analyze_single_text(self, text: str) -> Dict:
        """Analyze single text with parallel phishing model processing"""
        logger.info(f"🔍 Parallel phishing analysis: {text[:50]}...")
        
        if not self.api_key:
            logger.warning("Hugging Face API key not configured")
            return self._enhanced_local_analysis(text)
        
        # 🚀 PARALLEL EXECUTION with multiple models
        try:
            # Use all available models for better accuracy
            selected_models = self.models
            
            # Create parallel tasks with optimized timeouts
            tasks = [
                asyncio.create_task(
                    self._analyze_with_model(model, text),
                    name=f"model_{model['name']}"
                )
                for model in selected_models
            ]
            
            logger.info(f"🚀 Running {len(tasks)} models in parallel...")
            start_time = time.time()
            
            # Wait for ALL models to complete OR timeout
            try:
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=3.0  # Give enough time for all models
                )
            except asyncio.TimeoutError:
                logger.warning("⏱️ Some models timed out, using available results")
                results = []
                for task in tasks:
                    if task.done():
                        try:
                            results.append(task.result())
                        except Exception as e:
                            results.append(e)
                    else:
                        task.cancel()
                        results.append(None)
            
            # Process all results and find the best one
            best_result = None
            highest_confidence = 0.0
            all_reasons = []
            
            for i, result in enumerate(results):
                if isinstance(result, Exception) or result is None:
                    continue
                    
                if result and result.get('source') == 'huggingface':
                    confidence = result.get('confidence', 0.0)
                    is_suspicious = result.get('is_suspicious', False)
                    model_name = selected_models[i]['name']
                    
                    logger.info(f"📊 {model_name}: {'🚨' if is_suspicious else '✅'} {confidence:.1%}")
                    
                    # Collect reasons from all models
                    if is_suspicious:
                        all_reasons.extend(result.get('reasons', []))
                    
                    # Keep the result with highest confidence
                    if confidence > highest_confidence:
                        best_result = result
                        highest_confidence = confidence
            
            elapsed = time.time() - start_time
            
            if best_result:
                # Enhance with combined reasons from all models
                if all_reasons:
                    best_result['reasons'] = list(set(all_reasons))[:3]  # Remove duplicates, max 3
                
                logger.info(f"✅ Parallel analysis completed in {elapsed:.2f}s - Best: {highest_confidence:.1%}")
                return best_result
            
            logger.warning(f"⚠️ All models failed in {elapsed:.2f}s")
            
        except Exception as e:
            logger.error(f"💥 Parallel processing error: {e}")
        
        # Enhanced local fallback with phishing patterns
        logger.info("🔄 Using enhanced local phishing analysis")
        return self._enhanced_local_analysis(text)
    
    async def _analyze_with_model(self, model_config: Dict, text: str) -> Optional[Dict]:
        """Analyze with a specific phishing detection model"""
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"}
            
            # Prepare input optimized for different model types
            input_text = self._prepare_model_input(text, model_config)
            
            # Aggressive timeout for speed
            timeout = aiohttp.ClientTimeout(total=2.0)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    model_config['url'],
                    headers=headers,
                    json={"inputs": input_text}
                ) as response:
                    
                    if response.status == 200:
                        result = await response.json()
                        parsed = self._parse_model_result(result, text, model_config)
                        
                        if parsed:
                            logger.info(f"✅ {model_config['name']}: {parsed.get('confidence', 0):.1%}")
                            return parsed
                    else:
                        logger.warning(f"❌ {model_config['name']}: HTTP {response.status}")
                        return None
                        
        except asyncio.TimeoutError:
            logger.warning(f"⏱️ {model_config['name']}: Timeout")
            return None
        except Exception as e:
            logger.warning(f"💥 {model_config['name']}: {e}")
            return None
    
    def _prepare_model_input(self, text: str, model_config: Dict) -> str:
        """Prepare input optimized for different model types"""
        # Truncate long text to improve speed
        if len(text) > 512:
            text = text[:512] + "..."
        
        model_name = model_config['name']
        model_type = model_config.get('model_type', 'generic')
        
        # Different models need different input formats
        if model_type == 'phishing_classifier':
            # Phishing-specific models expect raw text
            return text
        elif model_type == 'spam_classifier':
            # SMS spam models work best with raw text
            return text
        elif model_type == 'toxic_classifier':
            # Toxic models expect raw text for toxicity scoring
            return text
        else:
            # Default: raw text
            return text
    
    def _parse_model_result(self, result: any, original_text: str, model_config: Dict) -> Optional[Dict]:
        """Parse results from different types of models"""
        try:
            predictions = []
            
            # Handle different response formats
            if isinstance(result, list):
                if len(result) > 0:
                    if isinstance(result[0], list):
                        predictions = result[0]
                    elif isinstance(result[0], dict):
                        predictions = result
            elif isinstance(result, dict):
                predictions = [result]
            
            if not predictions:
                return None
            
            # Extract suspicious vs legitimate scores based on model type
            suspicious_score = 0.0
            legitimate_score = 0.0
            model_threshold = model_config.get('threshold', 0.5)
            model_type = model_config.get('model_type', 'generic')
            
            for pred in predictions:
                label = pred.get('label', '').lower()
                score = pred.get('score', 0.0)
                
                if model_type == 'phishing_classifier':
                    # Look for phishing vs legitimate labels
                    if any(indicator in label for indicator in ['phishing', 'malicious', 'fraud']):
                        suspicious_score = max(suspicious_score, score)
                    elif any(indicator in label for indicator in ['legitimate', 'safe', 'clean']):
                        legitimate_score = max(legitimate_score, score)
                
                elif model_type == 'spam_classifier':
                    # Look for spam vs ham labels
                    if any(indicator in label for indicator in ['spam', 'scam']):
                        suspicious_score = max(suspicious_score, score)
                    elif any(indicator in label for indicator in ['ham', 'legitimate', 'clean']):
                        legitimate_score = max(legitimate_score, score)
                
                elif model_type == 'toxic_classifier':
                    # For toxic models, treat toxic as suspicious
                    if 'toxic' in label and score > 0.3:
                        suspicious_score = max(suspicious_score, score * 0.9)  # Scale toxic to suspicious
                    elif any(indicator in label for indicator in ['clean', 'safe']) and score > 0.7:
                        legitimate_score = max(legitimate_score, score)
                
                # Generic fallback - look for any suspicious indicators
                else:
                    if any(indicator in label for indicator in ['phishing', 'spam', 'scam', 'malicious', 'fraud', 'toxic']):
                        suspicious_score = max(suspicious_score, score)
                    elif any(indicator in label for indicator in ['legitimate', 'safe', 'clean', 'ham', 'normal']):
                        legitimate_score = max(legitimate_score, score)
            
            # Determine final classification
            is_suspicious = suspicious_score > model_threshold
            confidence = suspicious_score if is_suspicious else legitimate_score
            
            # Enhance with local analysis for better accuracy
            local_analysis = self._quick_local_check(original_text)
            
            # Combine AI + local for final decision
            if is_suspicious or local_analysis['is_suspicious']:
                final_confidence = max(confidence, local_analysis['confidence'])
                final_suspicious = True
                reasons = []
                
                if is_suspicious:
                    model_type_name = {
                        'phishing_classifier': 'Phishing detection',
                        'spam_classifier': 'Spam detection', 
                        'toxic_classifier': 'Toxic content detection'
                    }.get(model_type, 'AI model')
                    reasons.append(f"{model_type_name} flagged content ({confidence:.1%})")
                
                if local_analysis['is_suspicious']:
                    reasons.extend(local_analysis['reasons'])
                
                return {
                    'is_suspicious': True,
                    'confidence': final_confidence,
                    'risk_level': self._get_risk_level(final_confidence, True),
                    'reasons': reasons[:3],
                    'source': 'huggingface',
                    'model_used': model_config['name']
                }
            else:
                return {
                    'is_suspicious': False,
                    'confidence': max(legitimate_score, 0.6),
                    'risk_level': 'safe',
                    'reasons': [],
                    'source': 'huggingface',
                    'model_used': model_config['name']
                }
                
        except Exception as e:
            logger.error(f"Error parsing phishing result: {e}")
            return None
    
    def _quick_local_check(self, text: str) -> Dict:
        """Quick local phishing pattern check"""
        text_lower = text.lower()
        score = 0.0
        reasons = []
        
        # High-impact Singapore phishing patterns
        critical_patterns = [
            (['singpass', 'gov.sg'], 0.5, 'SingPass/Government impersonation'),
            (['dbs', 'ocbc', 'uob', 'posb'], 0.4, 'Banking impersonation'),
            (['suspended', 'terminated', 'blocked'], 0.4, 'Account threats'),
            (['urgent', 'immediate', 'expires'], 0.3, 'Urgency tactics'),
            (['verify', 'update', 'confirm'], 0.2, 'Credential requests'),
            (['click here', 'click now'], 0.3, 'Suspicious links'),
            (['won', 'winner', 'prize', 'lottery'], 0.5, 'Prize scam')
        ]
        
        for patterns, weight, reason in critical_patterns:
            if any(pattern in text_lower for pattern in patterns):
                score += weight
                reasons.append(reason)
        
        return {
            'is_suspicious': score > 0.4,
            'confidence': min(score, 0.9),
            'reasons': reasons[:2]
        }
    
    def _enhanced_local_analysis(self, text: str) -> Dict:
        """Enhanced local analysis as fallback"""
        local_check = self._quick_local_check(text)
        
        return {
            'is_suspicious': local_check['is_suspicious'],
            'confidence': local_check['confidence'],
            'risk_level': self._get_risk_level(local_check['confidence'], local_check['is_suspicious']),
            'reasons': local_check['reasons'],
            'source': 'local_enhanced'
        }
    
    # Keep your existing methods for page analysis
    async def analyze_page_chunks(self, chunks: List[Dict]) -> Dict:
        """Analyze multiple text chunks from a webpage using parallel processing"""
        logger.info(f"🔍 Analyzing {len(chunks)} text chunks with parallel processing")
        
        suspicious_chunks = []
        total_analyzed = 0
        
        # Process chunks in batches to avoid overwhelming the API
        batch_size = 3
        for i in range(0, min(len(chunks), 10), batch_size):  # Max 10 chunks total
            batch = chunks[i:i + batch_size]
            
            # Process batch in parallel
            batch_tasks = []
            for chunk in batch:
                text = chunk.get('text', '')
                if len(text) >= 20:  # Only analyze meaningful text
                    batch_tasks.append(self.analyze_single_text(text))
            
            if batch_tasks:
                # Wait for batch to complete
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
                
                for j, result in enumerate(batch_results):
                    if isinstance(result, Exception):
                        logger.warning(f"Batch analysis failed: {result}")
                        continue
                    
                    total_analyzed += 1
                    
                    if result.get('is_suspicious'):
                        chunk_data = batch[j] if j < len(batch) else {}
                        suspicious_chunks.append({
                            'text': chunk_data.get('text', '')[:200] + '...' if len(chunk_data.get('text', '')) > 200 else chunk_data.get('text', ''),
                            'confidence': result['confidence'],
                            'reasons': result['reasons'],
                            'risk_level': result['risk_level'],
                            'element_context': chunk_data.get('context', 'unknown')
                        })
                
                # Small delay between batches
                await asyncio.sleep(0.3)
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(suspicious_chunks, total_analyzed)
        
        return {
            'overall_risk': overall_risk,
            'suspicious_chunks': suspicious_chunks,
            'total_chunks_analyzed': total_analyzed,
            'summary': self._generate_summary(suspicious_chunks, total_analyzed, overall_risk)
        }
    
    def _get_risk_level(self, confidence: float, is_suspicious: bool) -> str:
        """Determine risk level based on confidence"""
        if not is_suspicious:
            return 'safe'
        elif confidence >= 0.8:
            return 'dangerous'
        else:
            return 'suspicious'
    
    def _calculate_overall_risk(self, suspicious_chunks: List, total_analyzed: int) -> str:
        """Calculate overall page risk"""
        if not suspicious_chunks:
            return 'safe'
        
        dangerous_count = sum(1 for chunk in suspicious_chunks if chunk['risk_level'] == 'dangerous')
        
        if dangerous_count > 0 or len(suspicious_chunks) >= 2:
            return 'dangerous'
        elif len(suspicious_chunks) > 0:
            return 'suspicious'
        else:
            return 'safe'
    
    def _generate_summary(self, suspicious_chunks: List, total_analyzed: int, overall_risk: str) -> str:
        """Generate summary message"""
        if overall_risk == 'safe':
            return f"Analyzed {total_analyzed} text sections - no phishing threats detected"
        
        count = len(suspicious_chunks)
        return f"🚨 Found {count} suspicious text section{'s' if count != 1 else ''} out of {total_analyzed} analyzed"
