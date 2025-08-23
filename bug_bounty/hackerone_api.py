#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced HackerOne API Client with AI Integration
Advanced bug bounty program intelligence and vulnerability correlation
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
from collections import defaultdict

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

log = logging.getLogger(__name__)

@dataclass
class H1Program:
    id: str
    name: str
    handle: str
    url: str
    platform: str = "HackerOne"
    state: str = "active"
    submission_state: Optional[str] = None
    offers_bounties: bool = False
    accepts_disclosure: bool = False
    min_bounty: Optional[float] = None
    max_bounty: Optional[float] = None
    asset_types: List[str] = None
    last_updated: Optional[datetime] = None
    vulnerability_count: int = 0
    avg_bounty: Optional[float] = None
    response_efficiency: Optional[Dict[str, Any]] = None

class EnhancedHackerOneClient:
    """
    Enhanced HackerOne API client with AI-powered analysis
    Features:
    - Real-time program data synchronization
    - AI-powered vulnerability trend analysis
    - Program recommendation engine
    - Automated target discovery from disclosed reports
    - Intelligence correlation with scan results
    """
    
    def __init__(self):
        self.api_key = os.getenv("HACKERONE_API_KEY", "").strip("[]'\"")
        self.api_identifier = os.getenv("HACKERONE_API_IDENTIFIER") or os.getenv("HACKERONE_API_USERNAME")
        self.base_url = "https://api.hackerone.com/v1"
        self.headers = {"Accept": "application/json", "User-Agent": "Rudra-Enhanced/3.0.0"}
        
        self.session = None
        self.program_cache = {}
        self.vulnerability_patterns = defaultdict(list)
        
        # AI coordinator
        self.ai_coordinator = None
        if AI_AVAILABLE:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
            except Exception as e:
                log.warning(f"AI coordinator initialization failed: {e}")
        
        if self.api_key and self.api_identifier:
            self.auth = (self.api_identifier, self.api_key)
            log.info("✅ Enhanced HackerOne API client initialized")
        else:
            self.auth = None
            log.warning("⚠️ HackerOne credentials missing - using public data only")

    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()

    async def _make_async_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Make asynchronous API request"""
        if not self.auth or not self.session:
            return {}

        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            auth = aiohttp.BasicAuth(self.api_identifier, self.api_key)
            
            async with self.session.get(url, auth=auth, headers=self.headers, params=params or {}) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    log.warning("🚫 Rate limited - waiting...")
                    await asyncio.sleep(60)
                    return await self._make_async_request(endpoint, params)
                else:
                    log.warning(f"❌ HackerOne API error {response.status}: {await response.text()}")
                    return {}

        except Exception as e:
            log.error(f"HackerOne API request failed: {e}")
            return {}

    def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
        """Synchronous API request (fallback)"""
        if not self.auth:
            return {}

        try:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            response = requests.get(
                url, 
                auth=self.auth, 
                headers=self.headers,
                params=params or {}, 
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                log.warning("🚫 Rate limited by HackerOne API")
                return {}
            else:
                log.warning(f"❌ HackerOne API error {response.status_code}")
                return {}

        except Exception as e:
            log.error(f"HackerOne API request error: {e}")
            return {}

    async def get_enhanced_programs(self, include_disabled: bool = False) -> List[H1Program]:
        """Get enhanced program data with AI analysis"""
        programs = []
        seen_handles = set()
        
        # Get programs from multiple endpoints
        endpoints_to_try = [
            ("hackers/me/reports", {"page[size]": 100}),
            ("hackers/hacktivity", {"page[size]": 100}),
            ("programs", {"page[size]": 100}) if self.auth else None
        ]
        
        for endpoint_data in endpoints_to_try:
            if endpoint_data is None:
                continue
                
            endpoint, params = endpoint_data
            data = await self._make_async_request(endpoint, params)
            
            if not data or 'data' not in data:
                continue
                
            for item in data['data']:
                program_data = self._extract_program_data(item)
                if program_data and program_data.handle not in seen_handles:
                    seen_handles.add(program_data.handle)
                    programs.append(program_data)
        
        # Enhance programs with AI analysis
        if self.ai_coordinator and programs:
            programs = await self._enhance_programs_with_ai(programs)
        
        # Cache results
        self.program_cache = {p.handle: p for p in programs}
        
        log.info(f"🎯 Retrieved {len(programs)} enhanced HackerOne programs")
        return programs

    def _extract_program_data(self, item: Dict[str, Any]) -> Optional[H1Program]:
        """Extract program data from API response"""
        try:
            # Handle different API response structures
            if 'relationships' in item and 'program' in item['relationships']:
                program_info = item['relationships']['program']['data']
                attrs = program_info.get('attributes', {})
            elif 'attributes' in item:
                attrs = item['attributes']
            else:
                return None
                
            handle = attrs.get('handle')
            if not handle:
                return None
                
            # Extract asset types
            asset_types = []
            if 'structured_scopes' in attrs:
                for scope in attrs.get('structured_scopes', []):
                    asset_type = scope.get('asset_type', '')
                    if asset_type and asset_type not in asset_types:
                        asset_types.append(asset_type)
            
            return H1Program(
                id=handle,
                name=attrs.get('name', handle),
                handle=handle,
                url=attrs.get('url', f"https://hackerone.com/{handle}"),
                state=attrs.get('state', 'active'),
                submission_state=attrs.get('submission_state'),
                offers_bounties=attrs.get('offers_bounties', False),
                accepts_disclosure=attrs.get('offers_public_disclosure', False),
                asset_types=asset_types,
                last_updated=datetime.now()
            )
            
        except Exception as e:
            log.error(f"Failed to extract program data: {e}")
            return None

    async def _enhance_programs_with_ai(self, programs: List[H1Program]) -> List[H1Program]:
        """Enhance programs with AI-powered analysis"""
        if not self.ai_coordinator:
            return programs
            
        try:
            # Analyze program patterns and trends
            program_data = [
                {
                    "name": p.name,
                    "handle": p.handle,
                    "asset_types": p.asset_types or [],
                    "offers_bounties": p.offers_bounties,
                    "state": p.state
                }
                for p in programs
            ]
            
            prompt = f"""Analyze these HackerOne bug bounty programs and provide insights:

Programs Data: {json.dumps(program_data[:20], indent=2)}  # Limit for prompt size

Provide analysis as JSON:
{{
  "program_categories": {{"category": "count"}},
  "high_value_programs": ["program_handles"],
  "trending_asset_types": ["asset_types"],
  "recommendations": ["recommendations"],
  "market_insights": {{"insight": "description"}}
}}
"""
            
            request = AIRequest(
                task_type="bug_bounty_analysis",
                prompt=prompt,
                context={"programs_count": len(programs)},
                require_json=True
            )
            
            response = await self.ai_coordinator.process_request(request)
            
            if response.success:
                ai_insights = self._parse_ai_insights(response.content)
                # Enhance programs with AI insights
                programs = self._apply_ai_insights_to_programs(programs, ai_insights)
                
        except Exception as e:
            log.error(f"AI program enhancement failed: {e}")
            
        return programs

    def _parse_ai_insights(self, content: str) -> Dict[str, Any]:
        """Parse AI insights from response"""
        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            
            if start >= 0 and end > start:
                json_str = content[start:end]
                return json.loads(json_str)
        except Exception as e:
            log.error(f"Failed to parse AI insights: {e}")
            
        return {}

    def _apply_ai_insights_to_programs(self, programs: List[H1Program], insights: Dict[str, Any]) -> List[H1Program]:
        """Apply AI insights to enhance program data"""
        high_value_programs = set(insights.get('high_value_programs', []))
        
        for program in programs:
            if program.handle in high_value_programs:
                program.min_bounty = 500  # Estimated based on AI analysis
                program.max_bounty = 10000  # Estimated based on AI analysis
                
        return programs

    async def get_disclosed_reports(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get disclosed vulnerability reports for intelligence"""
        disclosed_reports = []
        
        try:
            params = {
                "filter[disclosed]": "true",
                "page[size]": min(limit, 100),
                "sort": "-disclosed_at"
            }
            
            data = await self._make_async_request("reports", params)
            
            if data and 'data' in data:
                for report in data['data']:
                    attrs = report.get('attributes', {})
                    disclosed_reports.append({
                        "id": report.get('id'),
                        "title": attrs.get('title'),
                        "severity": attrs.get('severity_rating'),
                        "bounty": attrs.get('bounty_amount'),
                        "disclosed_at": attrs.get('disclosed_at'),
                        "weakness": attrs.get('weakness', {}),
                        "program_handle": self._extract_program_handle_from_report(report)
                    })
            
            # Analyze patterns in disclosed reports
            if disclosed_reports and self.ai_coordinator:
                await self._analyze_vulnerability_patterns(disclosed_reports)
                
        except Exception as e:
            log.error(f"Failed to get disclosed reports: {e}")
            
        return disclosed_reports

    def _extract_program_handle_from_report(self, report: Dict[str, Any]) -> Optional[str]:
        """Extract program handle from report data"""
        try:
            if 'relationships' in report and 'program' in report['relationships']:
                program_data = report['relationships']['program']['data']
                return program_data.get('attributes', {}).get('handle')
        except:
            pass
        return None

    async def _analyze_vulnerability_patterns(self, reports: List[Dict[str, Any]]):
        """Analyze vulnerability patterns using AI"""
        if not self.ai_coordinator:
            return
            
        try:
            # Group vulnerabilities by type
            vuln_patterns = defaultdict(list)
            for report in reports:
                weakness = report.get('weakness', {})
                weakness_name = weakness.get('name', 'Unknown')
                vuln_patterns[weakness_name].append({
                    "title": report.get('title'),
                    "severity": report.get('severity'),
                    "bounty": report.get('bounty')
                })
            
            # Store patterns for later use
            self.vulnerability_patterns.update(vuln_patterns)
            
            log.info(f"📊 Analyzed {len(reports)} disclosed reports, found {len(vuln_patterns)} vulnerability patterns")
            
        except Exception as e:
            log.error(f"Vulnerability pattern analysis failed: {e}")

    async def find_relevant_programs(self, target_domains: List[str]) -> List[H1Program]:
        """Find bug bounty programs relevant to target domains"""
        relevant_programs = []
        
        if not self.program_cache:
            await self.get_enhanced_programs()
        
        # Simple domain matching (can be enhanced with AI)
        for program in self.program_cache.values():
            program_relevance = self._calculate_program_relevance(program, target_domains)
            if program_relevance > 0.3:  # Threshold for relevance
                relevant_programs.append(program)
        
        # Sort by relevance and bounty potential
        relevant_programs.sort(
            key=lambda p: (p.offers_bounties, p.max_bounty or 0, len(p.asset_types or [])),
            reverse=True
        )
        
        return relevant_programs

    def _calculate_program_relevance(self, program: H1Program, target_domains: List[str]) -> float:
        """Calculate relevance score between program and target domains"""
        relevance_score = 0.0
        
        # Simple heuristic matching
        program_text = f"{program.name} {program.handle}".lower()
        
        for domain in target_domains:
            domain_parts = domain.lower().split('.')
            for part in domain_parts:
                if len(part) > 3 and part in program_text:
                    relevance_score += 0.3
                    
        # Boost score for programs with API asset types
        if program.asset_types:
            api_types = ['api', 'web application', 'mobile application']
            for asset_type in program.asset_types:
                if any(api_type in asset_type.lower() for api_type in api_types):
                    relevance_score += 0.2
                    
        return min(relevance_score, 1.0)

    async def get_vulnerability_trends(self) -> Dict[str, Any]:
        """Get vulnerability trends from disclosed reports"""
        if not self.vulnerability_patterns:
            await self.get_disclosed_reports(200)
        
        trends = {
            "most_common_vulnerabilities": [],
            "highest_bounty_types": [],
            "emerging_patterns": [],
            "recommendation": ""
        }
        
        # Analyze vulnerability patterns
        vuln_counts = {k: len(v) for k, v in self.vulnerability_patterns.items()}
        trends["most_common_vulnerabilities"] = sorted(
            vuln_counts.items(), key=lambda x: x[1], reverse=True
        )[:10]
        
        # Analyze bounty patterns
        bounty_by_type = defaultdict(list)
        for vuln_type, reports in self.vulnerability_patterns.items():
            bounties = [r.get('bounty', 0) for r in reports if r.get('bounty')]
            if bounties:
                bounty_by_type[vuln_type] = {
                    "avg_bounty": sum(bounties) / len(bounties),
                    "max_bounty": max(bounties),
                    "count": len(bounties)
                }
        
        trends["highest_bounty_types"] = sorted(
            bounty_by_type.items(), 
            key=lambda x: x[1]["avg_bounty"], 
            reverse=True
        )[:10]
        
        return trends

    def get_my_reports_enhanced(self) -> List[Dict[str, Any]]:
        """Get enhanced version of user's reports"""
        reports = []
        data = self._make_request("hackers/me/reports")
        
        if data and "data" in data:
            for report in data["data"]:
                attrs = report.get("attributes", {})
                
                # Enhanced report data
                enhanced_report = {
                    "id": report.get("id"),
                    "title": attrs.get("title"),
                    "state": attrs.get("state"),
                    "severity": attrs.get("severity_rating"),
                    "bounty_amount": attrs.get("bounty_amount"),
                    "created_at": attrs.get("created_at"),
                    "disclosed_at": attrs.get("disclosed_at"),
                    "triaged_at": attrs.get("triaged_at"),
                    "resolved_at": attrs.get("resolved_at"),
                    "weakness": attrs.get("weakness", {}),
                    "vulnerability_information": attrs.get("vulnerability_information", ""),
                    "program_handle": self._extract_program_handle_from_report(report)
                }
                
                reports.append(enhanced_report)
        
        return reports

    def get_program_statistics(self) -> Dict[str, Any]:
        """Get comprehensive program statistics"""
        if not self.program_cache:
            # Try to get programs synchronously for stats
            try:
                self.list_programs()  # Fallback to sync method
            except:
                pass
        
        stats = {
            "total_programs": len(self.program_cache),
            "bounty_programs": len([p for p in self.program_cache.values() if p.offers_bounties]),
            "active_programs": len([p for p in self.program_cache.values() if p.state == 'active']),
            "asset_type_distribution": defaultdict(int),
            "vulnerability_patterns_count": len(self.vulnerability_patterns),
            "api_credentials_valid": bool(self.auth),
            "last_updated": datetime.now().isoformat()
        }
        
        # Calculate asset type distribution
        for program in self.program_cache.values():
            if program.asset_types:
                for asset_type in program.asset_types:
                    stats["asset_type_distribution"][asset_type] += 1
        
        return stats

    def list_programs(self) -> List[Dict[str, Any]]:
        """Legacy method for backward compatibility"""
        programs = []
        seen_handles = set()
        
        # Try multiple endpoints for comprehensive data
        endpoints = [
            ("hackers/me/reports", {"page[size]": 100}),
            ("hackers/hacktivity", {"page[size]": 100})
        ]
        
        for endpoint, params in endpoints:
            data = self._make_request(endpoint, params)
            
            if not data or 'data' not in data:
                continue
                
            for item in data['data']:
                try:
                    # Extract program information
                    if 'relationships' in item and 'program' in item['relationships']:
                        program_info = item['relationships']['program']['data']
                        attrs = program_info.get('attributes', {})
                    else:
                        continue
                        
                    handle = attrs.get('handle')
                    if not handle or handle in seen_handles:
                        continue
                        
                    seen_handles.add(handle)
                    
                    programs.append({
                        "id": handle,
                        "name": attrs.get("name", handle),
                        "handle": handle,
                        "url": attrs.get("url", f"https://hackerone.com/{handle}"),
                        "platform": "HackerOne",
                        "state": attrs.get("state", "active"),
                        "submission_state": attrs.get("submission_state"),
                        "offers_bounties": attrs.get("offers_bounties", False)
                    })
                    
                except (KeyError, TypeError) as e:
                    log.debug(f"Skipping malformed program data: {e}")
                    continue
        
        log.info(f"🎯 Retrieved {len(programs)} HackerOne programs")
        return programs

    def search_programs_by_keyword(self, keyword: str) -> List[Dict[str, Any]]:
        """Search programs by keyword"""
        if not self.program_cache:
            self.list_programs()
        
        matching_programs = []
        keyword_lower = keyword.lower()
        
        for program in self.program_cache.values():
            if (keyword_lower in program.name.lower() or 
                keyword_lower in program.handle.lower() or
                (program.asset_types and any(keyword_lower in at.lower() for at in program.asset_types))):
                matching_programs.append({
                    "id": program.id,
                    "name": program.name,
                    "handle": program.handle,
                    "url": program.url,
                    "offers_bounties": program.offers_bounties,
                    "asset_types": program.asset_types
                })
        
        return matching_programs

# Enhanced usage example and testing
async def main():
    """Example usage of Enhanced HackerOne Client"""
    async with EnhancedHackerOneClient() as client:
        # Get enhanced programs with AI analysis
        programs = await client.get_enhanced_programs()
        print(f"Found {len(programs)} programs")
        
        # Get vulnerability trends
        trends = await client.get_vulnerability_trends()
        print(f"Vulnerability trends: {trends}")
        
        # Find relevant programs for target
        relevant = await client.find_relevant_programs(['example.com', 'api.example.com'])
        print(f"Found {len(relevant)} relevant programs")

if __name__ == "__main__":
    asyncio.run(main())

