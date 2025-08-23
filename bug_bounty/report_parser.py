#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Bug Bounty Report Parser with AI Integration
Advanced NLP and AI-powered vulnerability report analysis
"""

import json
import re
import logging
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import hashlib

# NLP libraries
try:
    import nltk
    from nltk.tokenize import word_tokenize, sent_tokenize
    from nltk.corpus import stopwords
    from nltk.tag import pos_tag
    NLP_AVAILABLE = True
except ImportError:
    NLP_AVAILABLE = False

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class VulnerabilityReport:
    title: str
    vulnerability_type: str
    cwe: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: str = "medium"
    summary: str = ""
    impact: str = ""
    poc: str = ""
    remediation: str = ""
    affected_urls: List[str] = None
    parameters: List[str] = None
    payload: Optional[str] = None
    discovered_by: Optional[str] = None
    bounty_amount: Optional[float] = None
    platform: Optional[str] = None
    ai_insights: Dict[str, Any] = None
    confidence_score: float = 0.0
    extracted_at: datetime = None

class EnhancedBugBountyReportParser:
    """
    Advanced bug bounty report parser with AI and NLP capabilities
    Features:
    - Multi-format report parsing (HackerOne, Bugcrowd, plain text)
    - AI-powered content understanding and categorization
    - Advanced NLP for entity extraction
    - Vulnerability pattern recognition
    - Impact assessment and severity scoring
    - PoC code extraction and analysis
    - Remediation recommendation generation
    """
    
    def __init__(self):
        # Vulnerability type patterns
        self.vuln_patterns = {
            'sql_injection': [
                r'sql\s*injection', r'sqli', r'union\s*select', r'or\s*1\s*=\s*1',
                r'database\s*error', r'syntax\s*error.*sql'
            ],
            'xss': [
                r'cross[\s\-]*site\s*scripting', r'xss', r'<script', r'javascript:',
                r'reflected\s*xss', r'stored\s*xss', r'dom\s*xss'
            ],
            'csrf': [
                r'cross[\s\-]*site\s*request\s*forgery', r'csrf', r'state\s*changing',
                r'anti[\s\-]*csrf\s*token'
            ],
            'idor': [
                r'insecure\s*direct\s*object\s*reference', r'idor', r'access\s*control',
                r'authorization\s*bypass', r'privilege\s*escalation'
            ],
            'authentication_bypass': [
                r'authentication\s*bypass', r'login\s*bypass', r'auth\s*bypass',
                r'session\s*fixation', r'weak\s*authentication'
            ],
            'information_disclosure': [
                r'information\s*disclosure', r'data\s*exposure', r'sensitive\s*information',
                r'directory\s*listing', r'debug\s*information'
            ],
            'rce': [
                r'remote\s*code\s*execution', r'rce', r'command\s*injection',
                r'code\s*injection', r'arbitrary\s*code'
            ],
            'lfi': [
                r'local\s*file\s*inclusion', r'lfi', r'directory\s*traversal',
                r'path\s*traversal', r'file\s*disclosure'
            ],
            'ssrf': [
                r'server[\s\-]*side\s*request\s*forgery', r'ssrf',
                r'internal\s*port\s*scan', r'localhost'
            ]
        }
        
        # Severity patterns
        self.severity_patterns = {
            'critical': [r'critical', r'9\.[0-9]', r'10\.0'],
            'high': [r'high', r'[7-8]\.[0-9]'],
            'medium': [r'medium', r'[4-6]\.[0-9]'],
            'low': [r'low', r'[1-3]\.[0-9]'],
            'info': [r'informational', r'info', r'0\.[0-9]']
        }
        
        # CWE patterns
        self.cwe_patterns = {
            'CWE-79': ['xss', 'cross-site scripting'],
            'CWE-89': ['sql injection', 'sqli'],
            'CWE-352': ['csrf', 'cross-site request forgery'],
            'CWE-22': ['path traversal', 'directory traversal'],
            'CWE-78': ['command injection'],
            'CWE-918': ['ssrf', 'server-side request forgery'],
            'CWE-862': ['authorization bypass', 'access control'],
            'CWE-200': ['information disclosure', 'data exposure']
        }
        
        # AI coordinator
        self.ai_coordinator = None
        if AI_AVAILABLE:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")

    def parse_report(self, report_text: str, report_metadata: Optional[Dict[str, Any]] = None) -> VulnerabilityReport:
        """Enhanced report parsing with AI assistance"""
        try:
            # Basic extraction
            basic_data = self._extract_basic_fields(report_text)
            
            # Advanced NLP extraction
            if NLP_AVAILABLE:
                nlp_data = self._extract_with_nlp(report_text)
                basic_data.update(nlp_data)
            
            # AI-powered enhancement
            ai_insights = {}
            if self.ai_coordinator:
                ai_insights = self._enhance_with_ai(report_text, basic_data)
            
            # Build vulnerability report
            report = VulnerabilityReport(
                title=basic_data.get('title', 'Unknown Vulnerability'),
                vulnerability_type=basic_data.get('vulnerability_type', 'Unknown'),
                cwe=basic_data.get('cwe'),
                cvss_score=basic_data.get('cvss_score'),
                severity=basic_data.get('severity', 'medium'),
                summary=basic_data.get('summary', ''),
                impact=basic_data.get('impact', ''),
                poc=basic_data.get('poc', ''),
                remediation=basic_data.get('remediation', ''),
                affected_urls=basic_data.get('affected_urls', []),
                parameters=basic_data.get('parameters', []),
                payload=basic_data.get('payload'),
                ai_insights=ai_insights,
                confidence_score=self._calculate_confidence(basic_data, ai_insights),
                extracted_at=datetime.now()
            )
            
            # Apply metadata if provided
            if report_metadata:
                report.discovered_by = report_metadata.get('researcher')
                report.bounty_amount = report_metadata.get('bounty')
                report.platform = report_metadata.get('platform')
            
            return report
            
        except Exception as e:
            log.error(f"Report parsing failed: {e}")
            return VulnerabilityReport(
                title="Parsing Error",
                vulnerability_type="unknown",
                summary=f"Failed to parse report: {str(e)}",
                extracted_at=datetime.now()
            )

    def _extract_basic_fields(self, report_text: str) -> Dict[str, Any]:
        """Extract basic fields using regex patterns"""
        data = {}
        
        # Title extraction
        title_patterns = [
            r"##?\s*Title:\s*(.*?)(?:\n|$)",
            r"##?\s*Summary:\s*(.*?)(?:\n|$)",
            r"^(.{10,100})(?:\n|$)",  # First substantial line
        ]
        
        for pattern in title_patterns:
            match = re.search(pattern, report_text, re.IGNORECASE | re.MULTILINE)
            if match:
                data['title'] = match.group(1).strip()
                break
        
        # Vulnerability type detection
        data['vulnerability_type'] = self._detect_vulnerability_type(report_text)
        
        # CWE extraction
        cwe_match = re.search(r'CWE[:\-\s]*(\d+)', report_text, re.IGNORECASE)
        if cwe_match:
            data['cwe'] = f"CWE-{cwe_match.group(1)}"
        else:
            # Try to map vulnerability type to CWE
            data['cwe'] = self._map_vuln_to_cwe(data['vulnerability_type'])
        
        # CVSS score extraction
        cvss_patterns = [
            r'CVSS[:\s]*([0-9]\.[0-9])',
            r'Score[:\s]*([0-9]\.[0-9])',
            r'Rating[:\s]*([0-9]\.[0-9])'
        ]
        
        for pattern in cvss_patterns:
            match = re.search(pattern, report_text, re.IGNORECASE)
            if match:
                try:
                    data['cvss_score'] = float(match.group(1))
                    break
                except ValueError:
                    continue
        
        # Severity detection
        data['severity'] = self._detect_severity(report_text, data.get('cvss_score'))
        
        # Section extraction
        sections = self._extract_sections(report_text)
        data.update(sections)
        
        # URL extraction
        data['affected_urls'] = self._extract_urls(report_text)
        
        # Parameter extraction
        data['parameters'] = self._extract_parameters(report_text)
        
        # Payload extraction
        data['payload'] = self._extract_payload(report_text)
        
        return data

    def _detect_vulnerability_type(self, text: str) -> str:
        """Detect vulnerability type using pattern matching"""
        text_lower = text.lower()
        scores = {}
        
        for vuln_type, patterns in self.vuln_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, text_lower))
                score += matches
            
            if score > 0:
                scores[vuln_type] = score
        
        if scores:
            return max(scores.items(), key=lambda x: x[1])[0]
        
        return "unknown"

    def _map_vuln_to_cwe(self, vuln_type: str) -> Optional[str]:
        """Map vulnerability type to most common CWE"""
        mapping = {
            'xss': 'CWE-79',
            'sql_injection': 'CWE-89',
            'csrf': 'CWE-352',
            'lfi': 'CWE-22',
            'rce': 'CWE-78',
            'ssrf': 'CWE-918',
            'idor': 'CWE-862',
            'information_disclosure': 'CWE-200'
        }
        
        return mapping.get(vuln_type)

    def _detect_severity(self, text: str, cvss_score: Optional[float] = None) -> str:
        """Detect severity from text or CVSS score"""
        # First try CVSS score
        if cvss_score:
            if cvss_score >= 9.0:
                return "critical"
            elif cvss_score >= 7.0:
                return "high"
            elif cvss_score >= 4.0:
                return "medium"
            elif cvss_score >= 0.1:
                return "low"
        
        # Then try text patterns
        text_lower = text.lower()
        for severity, patterns in self.severity_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    return severity
        
        return "medium"  # Default

    def _extract_sections(self, text: str) -> Dict[str, str]:
        """Extract structured sections from report"""
        sections = {}
        
        # Common section patterns
        section_patterns = {
            'summary': [
                r"##?\s*Summary:?\s*(.*?)(?=##|\n\n|\Z)",
                r"##?\s*Description:?\s*(.*?)(?=##|\n\n|\Z)",
                r"##?\s*Details:?\s*(.*?)(?=##|\n\n|\Z)"
            ],
            'impact': [
                r"##?\s*Impact:?\s*(.*?)(?=##|\n\n|\Z)",
                r"##?\s*Risk:?\s*(.*?)(?=##|\n\n|\Z)",
                r"##?\s*Consequence:?\s*(.*?)(?=##|\n\n|\Z)"
            ],
            'poc': [
                r"##?\s*(?:Proof\s*of\s*Concept|PoC|Steps\s*to\s*Reproduce):?\s*(.*?)(?=##|\Z)",
                r"##?\s*Reproduction:?\s*(.*?)(?=##|\Z)",
                r"##?\s*How\s*to\s*reproduce:?\s*(.*?)(?=##|\Z)"
            ],
            'remediation': [
                r"##?\s*(?:Remediation|Fix|Solution|Recommendation):?\s*(.*?)(?=##|\Z)",
                r"##?\s*How\s*to\s*fix:?\s*(.*?)(?=##|\Z)",
                r"##?\s*Mitigation:?\s*(.*?)(?=##|\Z)"
            ]
        }
        
        for section_name, patterns in section_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
                if match:
                    content = match.group(1).strip()
                    if content and len(content) > 10:  # Minimum content length
                        sections[section_name] = content
                        break
        
        return sections

    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from report text"""
        url_pattern = r'https?://[^\s<>"\[\]{}|\\^`]+'
        urls = re.findall(url_pattern, text)
        
        # Clean and deduplicate
        clean_urls = []
        seen = set()
        
        for url in urls:
            # Remove trailing punctuation
            url = re.sub(r'[.,;:!?]+$', '', url)
            if url not in seen and len(url) > 10:
                clean_urls.append(url)
                seen.add(url)
        
        return clean_urls

    def _extract_parameters(self, text: str) -> List[str]:
        """Extract parameter names from report"""
        # Common parameter patterns
        param_patterns = [
            r'parameter[:\s]+([a-zA-Z0-9_]+)',
            r'param[:\s]+([a-zA-Z0-9_]+)',
            r'&([a-zA-Z0-9_]+)=',
            r'\?([a-zA-Z0-9_]+)=',
            r'"([a-zA-Z0-9_]+)"\s*:',  # JSON parameters
            r"'([a-zA-Z0-9_]+)'\s*:",  # JSON parameters
        ]
        
        parameters = set()
        for pattern in param_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            parameters.update(matches)
        
        return list(parameters)

    def _extract_payload(self, text: str) -> Optional[str]:
        """Extract attack payload from report"""
        payload_patterns = [
            r"payload[:\s]+(.*?)(?:\n|$)",
            r"exploit[:\s]+(.*?)(?:\n|$)",
            r"injection[:\s]+(.*?)(?:\n|$)",
            r"<script[^>]*>.*?</script>",
            r"'\s*(?:union|or|and)\s+.*?--",
            r"javascript:[^\"'<>\s]+",
        ]
        
        for pattern in payload_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                payload = match.group(1) if match.groups() else match.group(0)
                if len(payload.strip()) > 3:
                    return payload.strip()
        
        return None

    def _extract_with_nlp(self, text: str) -> Dict[str, Any]:
        """Enhanced extraction using NLP techniques"""
        if not NLP_AVAILABLE:
            return {}
        
        try:
            # Ensure NLTK data is available
            try:
                nltk.data.find('tokenizers/punkt')
            except LookupError:
                nltk.download('punkt')
            
            try:
                nltk.data.find('corpora/stopwords')
            except LookupError:
                nltk.download('stopwords')
            
            # Tokenization and analysis
            sentences = sent_tokenize(text)
            words = word_tokenize(text.lower())
            
            # Remove stopwords
            stop_words = set(stopwords.words('english'))
            filtered_words = [w for w in words if w not in stop_words and w.isalpha()]
            
            # Extract key technical terms
            technical_terms = self._extract_technical_terms(filtered_words)
            
            # Analyze sentence structure for better summary
            important_sentences = self._find_important_sentences(sentences)
            
            return {
                'technical_terms': technical_terms,
                'key_sentences': important_sentences[:3],  # Top 3 sentences
                'word_count': len(words),
                'sentence_count': len(sentences)
            }
            
        except Exception as e:
            log.error(f"NLP extraction failed: {e}")
            return {}

    def _extract_technical_terms(self, words: List[str]) -> List[str]:
        """Extract technical security terms"""
        security_terms = {
            'vulnerability', 'exploit', 'payload', 'injection', 'bypass',
            'authentication', 'authorization', 'session', 'token', 'cookie',
            'parameter', 'header', 'request', 'response', 'server', 'client',
            'database', 'query', 'script', 'code', 'input', 'output',
            'validation', 'sanitization', 'encoding', 'filtering'
        }
        
        found_terms = [word for word in words if word in security_terms]
        return list(set(found_terms))

    def _find_important_sentences(self, sentences: List[str]) -> List[str]:
        """Find the most important sentences for summary"""
        scored_sentences = []
        
        important_keywords = [
            'vulnerability', 'exploit', 'impact', 'affected', 'allows',
            'bypass', 'inject', 'execute', 'access', 'disclosure'
        ]
        
        for sentence in sentences:
            if len(sentence.split()) < 5:  # Skip very short sentences
                continue
                
            score = 0
            sentence_lower = sentence.lower()
            
            # Score based on important keywords
            for keyword in important_keywords:
                if keyword in sentence_lower:
                    score += 1
            
            # Boost score for sentences with technical terms
            if any(term in sentence_lower for term in ['http', 'api', 'endpoint', 'parameter']):
                score += 1
            
            if score > 0:
                scored_sentences.append((sentence.strip(), score))
        
        # Sort by score and return top sentences
        scored_sentences.sort(key=lambda x: x[1], reverse=True)
        return [sentence for sentence, score in scored_sentences]

    async def _enhance_with_ai(self, report_text: str, basic_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance parsing with AI analysis"""
        if not self.ai_coordinator:
            return {}
        
        try:
            # Limit text for AI processing
            text_sample = report_text[:3000]  # First 3000 characters
            
            prompt = f"""Analyze this vulnerability report and provide insights:

Report Text:
{text_sample}

Current Analysis:
- Type: {basic_data.get('vulnerability_type', 'unknown')}
- Severity: {basic_data.get('severity', 'unknown')}
- CWE: {basic_data.get('cwe', 'unknown')}

Provide enhanced analysis as JSON:
{{
  "vulnerability_classification": {{
    "primary_type": "vulnerability_type",
    "secondary_types": ["additional_types"],
    "attack_vectors": ["vectors"],
    "affected_components": ["components"]
  }},
  "severity_assessment": {{
    "suggested_severity": "critical|high|medium|low",
    "severity_justification": "reasoning",
    "business_impact": "description"
  }},
  "technical_analysis": {{
    "root_cause": "description",
    "exploitation_complexity": "easy|medium|hard",
    "prerequisites": ["requirements"],
    "indicators": ["technical_indicators"]
  }},
  "recommendations": {{
    "immediate_actions": ["actions"],
    "long_term_fixes": ["fixes"],
    "detection_methods": ["methods"]
  }}
}}
"""
            
            request = AIRequest(
                task_type="vulnerability_analysis",
                prompt=prompt,
                temperature=0.2,
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                return self._parse_ai_insights(response.content)
            
        except Exception as e:
            log.error(f"AI enhancement failed: {e}")
        
        return {}

    def _parse_ai_insights(self, content: str) -> Dict[str, Any]:
        """Parse AI analysis response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI insights: {e}")
        
        return {}

    def _calculate_confidence(self, basic_data: Dict[str, Any], ai_insights: Dict[str, Any]) -> float:
        """Calculate confidence score for the parsing"""
        confidence = 0.0
        
        # Basic field completeness
        if basic_data.get('title'):
            confidence += 0.2
        if basic_data.get('vulnerability_type') != 'unknown':
            confidence += 0.3
        if basic_data.get('summary'):
            confidence += 0.2
        if basic_data.get('poc'):
            confidence += 0.2
        
        # AI enhancement bonus
        if ai_insights:
            confidence += 0.1
        
        return min(confidence, 1.0)

    def parse_multiple_reports(self, reports: List[Dict[str, Any]]) -> List[VulnerabilityReport]:
        """Parse multiple reports efficiently"""
        parsed_reports = []
        
        for report_data in reports:
            try:
                text = report_data.get('text', '')
                metadata = {
                    'researcher': report_data.get('researcher'),
                    'bounty': report_data.get('bounty_amount'),
                    'platform': report_data.get('platform'),
                    'report_id': report_data.get('id')
                }
                
                parsed = self.parse_report(text, metadata)
                parsed_reports.append(parsed)
                
            except Exception as e:
                log.error(f"Failed to parse report {report_data.get('id', 'unknown')}: {e}")
                continue
        
        return parsed_reports

    def get_parsing_statistics(self, reports: List[VulnerabilityReport]) -> Dict[str, Any]:
        """Get statistics about parsed reports"""
        if not reports:
            return {"total_reports": 0}
        
        stats = {
            "total_reports": len(reports),
            "vulnerability_types": {},
            "severity_distribution": {},
            "cwe_distribution": {},
            "avg_confidence": 0,
            "reports_with_poc": 0,
            "reports_with_remediation": 0,
            "platforms": {},
            "parsing_success_rate": 0
        }
        
        confidence_sum = 0
        successful_parses = 0
        
        for report in reports:
            # Vulnerability types
            vuln_type = report.vulnerability_type
            stats["vulnerability_types"][vuln_type] = stats["vulnerability_types"].get(vuln_type, 0) + 1
            
            # Severity distribution
            severity = report.severity
            stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1
            
            # CWE distribution
            if report.cwe:
                stats["cwe_distribution"][report.cwe] = stats["cwe_distribution"].get(report.cwe, 0) + 1
            
            # PoC and remediation
            if report.poc:
                stats["reports_with_poc"] += 1
            if report.remediation:
                stats["reports_with_remediation"] += 1
            
            # Platform distribution
            if report.platform:
                stats["platforms"][report.platform] = stats["platforms"].get(report.platform, 0) + 1
            
            # Confidence and success
            confidence_sum += report.confidence_score
            if report.confidence_score > 0.5:
                successful_parses += 1
        
        stats["avg_confidence"] = confidence_sum / len(reports)
        stats["parsing_success_rate"] = successful_parses / len(reports)
        
        return stats

# Usage example
if __name__ == "__main__":
    parser = EnhancedBugBountyReportParser()
    
    # Example report text
    sample_report = """
    ## Title: SQL Injection in User Search Feature

    **Vulnerability Type:** SQL Injection
    **CWE:** CWE-89
    **CVSS:** 8.5
    **Severity:** High

    ## Summary:
    The application's user search functionality is vulnerable to SQL injection attacks
    through the 'username' parameter, allowing attackers to bypass authentication
    and extract sensitive data from the database.

    ## Impact:
    An attacker can exploit this vulnerability to:
    - Bypass authentication mechanisms
    - Extract sensitive user data including passwords
    - Potentially gain administrative access to the system

    ## Proof of Concept:
    1. Navigate to https://example.com/search
    2. Enter the following payload in the username field: admin' OR '1'='1' --
    3. The application returns all user records, confirming the SQL injection

    ## Remediation:
    - Use parameterized queries instead of string concatenation
    - Implement proper input validation and sanitization
    - Apply the principle of least privilege to database connections
    """
    
    # Parse the report
    parsed = parser.parse_report(sample_report)
    
    print(f"Title: {parsed.title}")
    print(f"Type: {parsed.vulnerability_type}")
    print(f"Severity: {parsed.severity}")
    print(f"CWE: {parsed.cwe}")
    print(f"Confidence: {parsed.confidence_score:.2f}")
    print(f"URLs found: {len(parsed.affected_urls)}")
    print(f"Parameters: {parsed.parameters}")

