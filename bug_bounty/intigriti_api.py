#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Intigriti API Client with AI Integration```vanced bug bounty program intelligence```d market analysis
"""

import requests
import os
import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICo```inator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Fallback data
try:
    from .public_programs import EnhancedPublicB```tyPrograms
except ImportError:
    class EnhancedPublicBountyPrograms:
        @staticmethod
        def get_intigriti_programs():
            return []

log = logging.getLogger(__name__)

@dataclass
class IntigritiProgram:
    id: str
    name: str
    company_name: str
    handle: str
    url: str
    program_type: str = "bounty"
    state: str = "active"
    platform: str = "Intigriti"
    min_bounty: Optional[float] = None
    max_bounty: Optional[float] = None
    confidentiality_level: Optional```r] = None
    last_updated: Optional[datetime] = None
    targets: List[str] = None
    researcher_count: Optional[int] = None

class EnhancedIntigritiClient:
    """
    Enhanced Intigriti API client with comprehensive intelligence
    Features:
    - Multi-endpoint API discovery
    - AI-powered program analysis
    - European market focus intelligence
    - Advanced program categorization
    - Target correlation analysis
    """
    
    def __init__(self):
        self.api_token = os.getenv("INTIGRITI_API_TOKEN", "").strip("[]'\"")
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "Rudra-Enhanced/3.0.0"
        }
        
        if self.api_token:
            self.headers["Authorization"] = f"Bearer {self.api_token}"
            log.info("✅ Enhanced Intigriti API client initialized")
        else:
            log.warning("⚠️ INTIGRITI_API_TOKEN not set - using enhanced fallback data")
        
        self.program_cache = {}
        
        # AI coordinator
        self.ai_coordinator = None
        if AI_AVAILABLE:
            try:
                self.ai_coordinator = AdvancedAICo```inator()
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")

    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make API request to Intigriti"""
        try:
            response = requests.get(endpoint, headers=self.headers, params=params``` {}, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                log.warning("🔐 Intigriti API authentication faile```
                return {}
            elif response.status_code == 429:
                log.warning("🚫 Intigriti API rate limited")
                return {}
            else:
                log.debug(f"Intigriti API response {response.status_code}: {response.text[:200]}")
                return {}
                
        except Exception as e:
            log.error(f"Intigriti API request failed: {e}")
            return {}

    def list_programs(self, program_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get enhanced Intigriti programs with AI analysis```
        
        # Try multiple API endpoints
        api_programs = self._try_multiple_api_endpoints(program_type)
        if api_programs:
            log.info(f"🎯 Retrieved {len(api_programs)} programs from Intigriti API")
            return api_programs
        
        # Enhanced fallback data
        log.info("📋 Using enhanced Intigriti fallback data")
        fallback_programs = EnhancedPublicBountyPrograms.get```tigriti_programs()
        
        # Filter by type if specified
        if program_type:
            fallback_programs = [
                p for p in fallback_programs 
                if p.get("type", "bounty").lower() == program_type.lower()
            ]
        
        # Enhance with AI analysis
        enhanced_programs = self._enhance_programs_with_intelligence```llback_programs)
        return enhanced_programs

    def _try_multiple_api_endpoints(self, program_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Try multiple Intigriti API endpoints"""```      endpoints = [
            "https://api.intigriti.com/researcher/programs",
            "https://app.intigriti.com/api/researcher/programs",
            "https://api.intigriti.com/v1/programs",
            "https://intigriti.com/api/programs",
            "https://app.intigriti.com/api/v1/programs/public"
        ]
        
        for endpoint in endpoints:
            try:
                params = {"limit": 100}
                if program_type:
                    params["type"] = program_type
                    
                data = self._make_request(endpoint, params)
                
                if data and self._is_valid_programs_```ponse(data):
                    programs = self._parse_api```ograms(data)
                    if programs:
                        log.info(f"✅ Intigriti API working at {endpoint}")
                        return programs
                        
            except Exception as e:
                log.debug(f"Endpoint {endpoint} failed: {e}")
                continue
        
        return []

    def _is_valid_programs_response(self, data: Dict[str, Any]) -> bool:
        """Check if response contains valid program data"""
        if not isinstance(data, dict):
            return False
            
        # Check for program data indicators
        indicators = ['programs', 'data', 'results', 'items', 'engagements']
        return any(key in data for key in indicators)

    def _parse_api_programs(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse programs from API response"""
        programs = []
        
        # Handle different response structures
        program_list = (
            data.get('programs') or 
            data.get('data') or 
            data.get('results') or 
            data.get('items') or
            data.get('engagements') or
            []
        )
        
        if not isinstance(program_list, list):
            return []
            
        for program in program_list:
            if not isinstance(program, dict):
                continue
                
            parsed = self._parse_single_program(program)
            if parsed:
                programs.append(parsed)
        
        return programs

    def _parse_single_program(self, program: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse single program from API response"""
        try:
            program_id = program.get('id') or program.get('programId')
            name = program.get('name') or program.get('programName')
            company = program.get('company_name') or program.get('companyName') or program.get('company')
            handle = program.get('handle') or program.get('slug')
            
            if not program_id or not name:
                return None
                
            return {
                "id": str(program_id),
                "name": name,
                "company_name": company or```me,
                "handle": handle or```me.lower().replace(' ', '-'),
                "url": program.get('url') or f"https://app.intigriti.com/programs/{handle}",
                "type": program.get('type', 'bounty'),
                "state": program.get('status') or program.get('state', 'active'),
                "platform": "Intigriti",
                "min_bounty": program.```('min_bounty') or program.get('minBounty'),
                "max_bounty": program.get('max_bounty') or program.get('maxBounty'),
                "confidentiality_level": program.get('confidentiality'),
                "targets": program.get('targets', []),
                "last_updated": datetime.now```isoformat()
            }
            
        except Exception as e:
            log.error(f"Failed to parse Intigriti program: {e}")
            return None

    def _enhance_programs_with_intelligence```lf, programs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enhance programs with AI intelligence and market data```
        enhanced = []
        
        for program in programs:
            enhanced_program = program```py()
            
            # Add European market intelligence
            enhanced_program.update(self._add_european_market_context(program))
            
            # Add enhanced metadata
            enhanced_program.update({
                "last_updated": datetime.now().isoformat(),
                "researcher_count":```lf._estimate_researcher_count(program),
                "program_maturity": self._assess```ogram_maturity(program),
                "market_position": self._analyze_market_position```ogram),
                "enhanced_metadata": {
                    "data_source": "enhanced_fall```k",
                    "ai_enriched": bool(self.ai_coordinator),
                    "last_enriched": datetime.now().isoformat(),
                    "confidence": 0.7
                }
            })
            
            enhanced.append(enhanced_program)
        
        return enhanced

    def _add_european_market_context(self, program: Dict[str, Any]) -> Dict[str, Any]:
        """Add European market context``` programs"""
        european_companies = {
            'personio': 'Germany',
            'simscale': 'Germany', 
            'intigriti': 'Belgium',
            'trivago': 'Germany',
            'klarna': 'Sweden',
            'spotify': 'Sweden',
            'adyen': 'Netherlands'
        }
        
        company_name = program.get('company_name', '').lower()
        handle = program.get('handle', '').lower()
        
        context = {
            "regional_focus": "Europe",
            "compliance_frameworks": ["GDPR", "PCI-DSS", "ISO27001"],
            "market_segment": "European Tech",
        }
        
        # Identify country if possible```      for company, country in european_companies.items```
            if company in company_name or```mpany in handle:
                context["country"] = country
                context["regulatory_environment"] = f"{country} + EU"
                break
        else:
            context["country"] = "Unknown"
            context["regulatory_environment"] = "EU"
        
        return {"european_context": context}

    def _estimate_researcher_count(self, program: Dict[str, Any]) -> int:
        """Estimate researcher count based on program characteristics"""
        base_count = 50
        
        # Adjust based on program characteristics
        if program.get('max_bounty', 0) > 5000:
            base_count += 100
        elif program.get('max_bounty', 0) > 2000:
            base_count += 50
            
        if program.get('type') == 'vdp':
            base_count -= 20
            
        # Add some randomness based on program name```      variation = hash(program.get('name', '')) % 50
        return base_count + variation

    def _assess_program_maturity(self, program: Dict[str, Any]) -> str:
        """Assess program maturity level```
        score = 0
        
        if program.get('max_bounty', 0) > 3000:
            score += 2
        if program.get('company_name') in ['Personio', 'SimScale', 'Intigriti']:
            score += 2
        if program.get('type') == 'bounty':
            score += 1
            
        if score >= 4:
            return "mature"
        elif score >= 2:
            return "developing"
        else:
            return "new"

    def _analyze_market_position(self, program: Dict[str, Any]) -> str:
        """Analyze program's market position"""
        company = program.get('company_name', '').lower()
        
        enterprise_indicators = ['enterprise', 'saas', 'platform', 'cloud']
        startup_indicators = ['startup', 'app', 'tool', 'service']
        
        if any(indicator in company for indicator in enterprise```dicators):
            return "enterprise"
        elif any(indicator in company for indicator in startup_indicators):
            return "startup"
        else:
            return "mid-market"

    async def analyze_european_market_```nds(self) -> Dict[str, Any]:
        """Analyze European bug bounty market trends"""
        programs = self.list_programs()
        
        trends = {
            "total_european_programs": len(programs),
            "country_distribution": {},
            "bounty_ranges": {"low": 0, "medium": 0, "high": 0, "very_high": 0},
            "compliance_focus": {},
            "market_insights": [],
            "growth_indicators": {}
        }
        
        # Analyze country distribution
        for program in programs:
            country = program.get('european_context', {}).get('country', 'Unknown')
            trends["country_distribution"][country] = trends["country_distribution"].get(country, 0) + 1
            
            # Analyze bounty ranges```          max_bounty = program.get('max_bounty', 0)
            if isinstance(max_bounty, (int, float)):
                if max_bounty >= 10000:
                    trends["bounty_ranges"]["very_high"] += 1
                elif max_bounty >= 5000:
                    trends["bounty_ranges"]["high"] += 1
                elif max_bounty >= 1000:
                    trends["bounty_ranges"]["medium"] += 1
                else:
                    trends["bounty_ranges"]["low"] += 1
        
        # Add AI insights if available
        if self.ai_coordinator:
            ai_insights = await self._get_ai_market_insights(programs)
            trends["ai_insights"] = ai_insights
        
        return trends

    async def _get_ai_market_insights(self, programs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get AI insights about European market"""
        if not self.ai_coordinator:
            return {}
            
        try:
            program_summary = [
                {
                    "name": p.get('name'),
                    "country": p.get('european_context', {}).get('country'),
                    "max_bounty": p.get('max_bounty'),
                    "maturity": p.get('program_maturity')
                }
                for p in programs[:30]
            ]
            
            prompt = f"""Analyze these European bug bounty programs for```rket insights:

Programs: {json.dumps(program_summary, indent=2)}

Provide analysis as JSON:
{{
  "european_market_trends": {{
    "dominant_countries": [],
    "average_bounty_trend": "increasing|stable|decreasing",
    "market_maturity": "emerging|growing```ture",
    "unique_characteristics": []
  }},
  "growth_opportunities": [],
  "regulatory_impact": {{
    "gdpr_influence": "description",
    "compliance_drivers": []
  }},
  "recommendations": []
}}
"""
            
            request = AIRequest(
                task_type="european_market_analysis",
                prompt=prompt,
                context={"program_count": len(programs)},
                require_json=True
            )
            
            response = await self.ai_```rdinator.process_request(request)
            
            if response.success:
                return self._parse_ai_response(response.content)
                
        except Exception as e:
            log.error(f"AI market analysis failed: {e}")
            
        return {}

    def _parse_ai_response(self, content: str) -> Dict[str, Any]:
        """Parse AI analysis response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI response: {e}")
            
        return {}

    def search_programs_by_criteria(self, criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Search programs by multiple criteria"""
        programs = self.list_programs()
        matching_programs = []
        
        for program in programs:
            score = 0
            
            # Country criteria
            if criteria.get('country'):
                program_country = program.get('european_context', {}).get('country', '')
                if criteria['country'].lower() in program_country.lower():
                    score += 0.3
                    
            # Bounty range criteria
            if criteria.get('min_bounty'):
                program_max = program.get('max_bounty', 0)
                if program_max >= criteria['min_bounty']:
                    score += 0.2
                    
            # Program type criteria
            if criteria.get('program_type'):
                if program.get('type') == criteria['program_type']:
                    score += 0.2
                    
            # Company size criteria
            if criteria.get('company_size'):
                program_position = program.get('market_position', '')
                if criteria['company_size'] in program_position:
                    score += 0.1
                    
            # Text search criteria
            if criteria.get('search_term'):
                search_term = criteria['search_term'].lower()
                searchable_text = f"{program.get('name', '')} {program.get('company_name', '')}".lower()
                if search_term in searchable_text:```                  score += 0.2
            
            if score > 0.2:  # Minimum relevance threshold
                program_copy = program.copy()
                program_copy['relevance_score'] = score
                matching_programs.append(program_copy)
        
        # Sort by relevance
        matching_programs.sort(key=lambda x: x.get('relevance_score', 0), reverse=True)
        return matching_programs

    def get_program_recommendations(self, target_profile: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get personalized program```commendations"""
        programs = self.list_programs()
        recommendations = []
        
        researcher_level = target_profile.get('experience_level', 'beginner')
        preferred_countries = target_profile.get('preferred_countries', [])
        min_bounty = target_profile.get('min_bounty_preference', 0)
        
        for program in programs:
            recommendation_score = 0
            reasons = []
            
            # Experience level matching
            maturity = program.get('program_maturity', 'new')
            if researcher_level == 'beg```er' and maturity in ['new', 'developing']:
                recommendation_score += ```
                reasons.append("Good for beginners")
            elif researcher_level == 'intermediate' and maturity ==```eveloping':
                recommendation_score += ```
                reasons.append("Suitable for intermediate researchers")
            elif researcher_level == 'expert' and maturity == 'mature```                recommendation_score += 0.5
                reasons.append("Challenging for experts")
            
            # Geographic preferences
            program_country = program.get('european_context', {}).get('country', '')
            if preferred_countries and program_country in preferred_countries:
                recommendation_score += 0.2
                reasons.append(f"Located in preferred country: {program_country}")
            
            # Bounty preferences
            max_bounty = program.get('max_bounty', 0)
            if max_bounty >= min_bounty```               recommendation_score += 0.2
                reasons.append(f"Meets bounty expectations: €{max_bounty}")
            
            # European context bonus
            if program.get('european_context'):
                recommendation_score += 0.1
                reasons.append("Strong European presence")
            
            if recommendation_score > 0.3:
                program_copy = program.copy()
                program_copy.update({
                    'recommendation```ore': recommendation_score,```                  'recommendation_reasons': reasons,```                  'match_percentage```int(recommendation_score * 100)
                })
                recommendations.appen```rogram_copy)
        
        # Sort by recommendation score
        recommendations.sort(key=lambda x: x.get('recommendation_score', 0), reverse=True)
        return recommendations[:10]  # Top 10 recommendations

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive Intigriti statistics"""
        programs = self.list_programs()
        
        stats = {
            "total_programs": len(programs),
            "platform": "Intigriti",
            "regional_focus": "Europe",
            "program_types": {},
            "bounty_statistics": {
                "avg_max_bounty": 0,
                "median_max_bounty": 0,
                "bounty_ranges": {"€0-1000": 0, "€1000-5000": 0, "€5000+": 0}
            },
            "country_coverage": {},
            "maturity_distribution": {},
            "compliance_focus": ["GDPR", "PCI-DSS", "ISO27001"],
            "last_updated": datetime.now().isoformat(),
            "data_quality": "enhanced_```lback" if not```lf.api_token```se "api"
        }
        
        bounties = []
        
        for program in programs:
            # Program types
            prog_type = program.get('type', 'bounty')
            stats["program_types"][prog_type] = stats["program_types"].get(prog_type, 0) + 1
            
            # Country distribution
            country = program.get('european_context', {}).get('country', 'Unknown')
            stats["country_coverage"][country] = stats["country_coverage"].get(country, 0) + 1
            
            # Maturity distribution
            maturity = program.get('program_maturity', 'unknown')
            stats["maturity_distribution"][maturity] = stats["maturity_distribution"].get(maturity, 0) + 1
            
            # Bounty analysis
            max_bounty = program.get('max_bounty', 0)
            if isinstance(max_bounty, (int, float)) and max_bounty > 0:
                bounties.append(max_bounty)
                
                if max_bounty >= 5000:
                    stats["bounty_statistics"]["bounty_ranges"]["€5000+"] += 1
                elif max_bounty >= 1000:
                    stats["bounty_statistics"]["bounty_ranges"]["€1000-5000"] += 1
                else:
                    stats["bounty_statistics"]["bounty_ranges"]["€0-1000"] += 1
        
        # Calculate bounty statistics
        if bounties:
            stats["bounty_statistics"]["avg_max_bounty"] = sum(bounties) / len(bounties)
            stats["bounty_statistics"]["median_max_bounty"] = sorted(bounties)[len(bounties)//2]
        
        return stats

# Usage example
if __name__ == "__main__":
    client = EnhancedIntigritiClient()
    
    # Get programs
    programs = client.list_programs()
    print(f"Found {len(programs)} Intigriti programs")
    
    # Get recommendations
    profile = {
        'experience_level': 'intermediate',
        'preferred_countries': ['Germany', 'Netherlands'],
        'min_bounty_preference': 1000
    }
    recommendations = client.get_program_recommendations(profile)
    print(f"Found {len(recommendations)} recommendations")
    
    # Get statistics
    stats = client.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")

