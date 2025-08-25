#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NIST NVD Integration for Real-time Vulnerability Intelligence
CVE data aggregation and analysis for enhanced threat detection
"""

import os
import json
import logging
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import hashlib
from collections import defaultdict
import sqlite3
import threading
import time

log = logging.getLogger(__name__)

@dataclass
class CVEData:
    cve_id: str
    description: str
    cvss_v3_score: float
    cvss_v2_score: Optional[float]
    severity: str
    published_date: datetime
    last_modified: datetime
    cwe_ids: List[str]
    cpe_matches: List[str]
    references: List[str]
    exploitability_score: Optional[float]
    impact_score: Optional[float]
    attack_vector: Optional[str]
    attack_complexity: Optional[str]
    privileges_required: Optional[str]
    user_interaction: Optional[str]
    scope: Optional[str]
    confidentiality_impact: Optional[str]
    integrity_impact: Optional[str]
    availability_impact: Optional[str]

class NVDIntegration:
    """
    Advanced NIST NVD integration for real-time vulnerability intelligence
    Features:
    - Real-time CVE data synchronization
    - CVSS scoring and risk assessment
    - CPE matching for technology stack analysis
    - Exploit prediction and trend analysis
    - Custom vulnerability database with ML enhancement
    """
    
    def __init__(self, api_key: Optional[str] = None, cache_dir: str = "./nvd_cache"):
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.cache_dir = cache_dir
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = None
        self.db_path = os.path.join(cache_dir, "nvd_cache.db")
        self.last_sync = None
        self.sync_lock = threading.Lock()
        
        # Rate limiting (NVD allows 5 requests per 30 seconds without API key, 50 with key)
        self.rate_limit = 50 if self.api_key else 5
        self.rate_window = 30
        self.request_times = []
        
        os.makedirs(cache_dir, exist_ok=True)
        self.initialize_database()
        
        log.info("🔍 NVD Integration initialized")

    def initialize_database(self):
        """Initialize SQLite database for caching CVE data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create CVEs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_v3_score REAL,
                    cvss_v2_score REAL,
                    severity TEXT,
                    published_date TEXT,
                    last_modified TEXT,
                    cwe_ids TEXT,
                    cpe_matches TEXT,
                    references TEXT,
                    exploitability_score REAL,
                    impact_score REAL,
                    attack_vector TEXT,
                    attack_complexity TEXT,
                    privileges_required TEXT,
                    user_interaction TEXT,
                    scope TEXT,
                    confidentiality_impact TEXT,
                    integrity_impact TEXT,
                    availability_impact TEXT,
                    raw_data TEXT,
                    created_at TEXT
                )
            ''')
            
            # Create indexes for fast queries
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_severity ON cves(severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_published ON cves(published_date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cvss ON cves(cvss_v3_score)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_cwe ON cves(cwe_ids)')
            
            # Create threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intel (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    cve_id TEXT,
                    exploit_available BOOLEAN,
                    exploit_maturity TEXT,
                    threat_actor_groups TEXT,
                    attack_patterns TEXT,
                    mitigation_strategies TEXT,
                    business_impact TEXT,
                    created_at TEXT,
                    FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
                )
            ''')
            
            conn.commit()
            conn.close()
            log.info("✅ NVD database initialized")
            
        except Exception as e:
            log.error(f"❌ Failed to initialize NVD database: {e}")

    async def _make_request(self, url: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """Make rate-limited request to NVD API"""
        try:
            # Rate limiting
            await self._wait_for_rate_limit()
            
            headers = {"Accept": "application/json"}
            if self.api_key:
                headers["apiKey"] = self.api_key
                
            if not self.session:
                self.session = aiohttp.ClientSession()
                
            async with self.session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return data
                elif response.status == 429:
                    log.warning("🚫 Rate limited by NVD API - waiting...")
                    await asyncio.sleep(30)
                    return await self._make_request(url, params)
                else:
                    log.error(f"❌ NVD API request failed: {response.status}")
                    return None
                    
        except Exception as e:
            log.error(f"❌ NVD API request error: {e}")
            return None

    async def _wait_for_rate_limit(self):
        """Wait if necessary to respect rate limits"""
        now = time.time()
        
        # Remove old request times
        self.request_times = [t for t in self.request_times if now - t < self.rate_window]
        
        # Wait if we're at the rate limit
        if len(self.request_times) >= self.rate_limit:
            sleep_time = self.rate_window - (now - self.request_times[0]) + 1
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        
        # Record this request
        self.request_times.append(now)

    async def sync_recent_cves(self, days_back: int = 7) -> Dict[str, Any]:
        """Synchronize recent CVEs from NVD"""
        try:
            with self.sync_lock:
                log.info(f"🔄 Syncing CVEs from last {days_back} days...")
                
                end_date = datetime.now()
                start_date = end_date - timedelta(days=days_back)
                
                params = {
                    "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                    "resultsPerPage": 2000
                }
                
                total_synced = 0
                start_index = 0
                
                while True:
                    params["startIndex"] = start_index
                    data = await self._make_request(self.base_url, params)
                    
                    if not data or 'vulnerabilities' not in data:
                        break
                    
                    vulnerabilities = data['vulnerabilities']
                    if not vulnerabilities:
                        break
                    
                    # Process each CVE
                    for vuln in vulnerabilities:
                        cve_data = self._parse_cve_data(vuln)
                        if cve_data:
                            self._store_cve_data(cve_data)
                            total_synced += 1
                    
                    # Check if there are more results
                    total_results = data.get('totalResults', 0)
                    start_index += len(vulnerabilities)
                    
                    if start_index >= total_results:
                        break
                    
                    # Small delay between requests
                    await asyncio.sleep(0.1)
                
                self.last_sync = datetime.now()
                
                log.info(f"✅ Synced {total_synced} CVEs from NVD")
                
                return {
                    "status": "success",
                    "synced_count": total_synced,
                    "sync_timestamp": self.last_sync.isoformat(),
                    "date_range": {
                        "start": start_date.isoformat(),
                        "end": end_date.isoformat()
                    }
                }
                
        except Exception as e:
            log.error(f"❌ CVE sync failed: {e}")
            return {"status": "error", "error": str(e)}

    def _parse_cve_data(self, vuln_data: Dict[str, Any]) -> Optional[CVEData]:
        """Parse CVE data from NVD API response"""
        try:
            cve = vuln_data.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                return None
            
            # Extract description
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Extract CVSS scores
            metrics = cve.get('metrics', {})
            cvss_v3_score = None
            cvss_v2_score = None
            severity = "UNKNOWN"
            attack_vector = None
            attack_complexity = None
            privileges_required = None
            user_interaction = None
            scope = None
            confidentiality_impact = None
            integrity_impact = None
            availability_impact = None
            exploitability_score = None
            impact_score = None
            
            # CVSS v3.x
            cvss_v3_data = metrics.get('cvssMetricV31') or metrics.get('cvssMetricV30')
            if cvss_v3_data:
                cvss_v3 = cvss_v3_data[0]  # Take first one
                cvss_data = cvss_v3.get('cvssData', {})
                cvss_v3_score = cvss_data.get('baseScore')
                severity = cvss_data.get('baseSeverity', 'UNKNOWN')
                attack_vector = cvss_data.get('attackVector')
                attack_complexity = cvss_data.get('attackComplexity')
                privileges_required = cvss_data.get('privilegesRequired')
                user_interaction = cvss_data.get('userInteraction')
                scope = cvss_data.get('scope')
                confidentiality_impact = cvss_data.get('confidentialityImpact')
                integrity_impact = cvss_data.get('integrityImpact')
                availability_impact = cvss_data.get('availabilityImpact')
                exploitability_score = cvss_v3.get('exploitabilityScore')
                impact_score = cvss_v3.get('impactScore')
            
            # CVSS v2
            cvss_v2_data = metrics.get('cvssMetricV2')
            if cvss_v2_data:
                cvss_v2 = cvss_v2_data[0]
                cvss_v2_score = cvss_v2.get('cvssData', {}).get('baseScore')
            
            # Extract CWE IDs
            weaknesses = cve.get('weaknesses', [])
            cwe_ids = []
            for weakness in weaknesses:
                for desc in weakness.get('description', []):
                    if desc.get('lang') == 'en':
                        cwe_ids.append(desc.get('value', ''))
            
            # Extract CPE matches
            configurations = cve.get('configurations', [])
            cpe_matches = []
            for config in configurations:
                for node in config.get('nodes', []):
                    for cpe_match in node.get('cpeMatch', []):
                        cpe_matches.append(cpe_match.get('criteria', ''))
            
            # Extract references
            references = []
            for ref in cve.get('references', []):
                references.append(ref.get('url', ''))
            
            # Parse dates
            published_date = datetime.fromisoformat(cve.get('published', '').replace('Z', '+00:00'))
            last_modified = datetime.fromisoformat(cve.get('lastModified', '').replace('Z', '+00:00'))
            
            return CVEData(
                cve_id=cve_id,
                description=description,
                cvss_v3_score=cvss_v3_score or 0.0,
                cvss_v2_score=cvss_v2_score,
                severity=severity,
                published_date=published_date,
                last_modified=last_modified,
                cwe_ids=cwe_ids,
                cpe_matches=cpe_matches,
                references=references,
                exploitability_score=exploitability_score,
                impact_score=impact_score,
                attack_vector=attack_vector,
                attack_complexity=attack_complexity,
                privileges_required=privileges_required,
                user_interaction=user_interaction,
                scope=scope,
                confidentiality_impact=confidentiality_impact,
                integrity_impact=integrity_impact,
                availability_impact=availability_impact
            )
            
        except Exception as e:
            log.error(f"❌ Failed to parse CVE data: {e}")
            return None

    def _store_cve_data(self, cve_data: CVEData):
        """Store CVE data in local database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO cves (
                    cve_id, description, cvss_v3_score, cvss_v2_score, severity,
                    published_date, last_modified, cwe_ids, cpe_matches, references,
                    exploitability_score, impact_score, attack_vector, attack_complexity,
                    privileges_required, user_interaction, scope,
                    confidentiality_impact, integrity_impact, availability_impact,
                    raw_data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_data.cve_id,
                cve_data.description,
                cve_data.cvss_v3_score,
                cve_data.cvss_v2_score,
                cve_data.severity,
                cve_data.published_date.isoformat(),
                cve_data.last_modified.isoformat(),
                json.dumps(cve_data.cwe_ids),
                json.dumps(cve_data.cpe_matches),
                json.dumps(cve_data.references),
                cve_data.exploitability_score,
                cve_data.impact_score,
                cve_data.attack_vector,
                cve_data.attack_complexity,
                cve_data.privileges_required,
                cve_data.user_interaction,
                cve_data.scope,
                cve_data.confidentiality_impact,
                cve_data.integrity_impact,
                cve_data.availability_impact,
                json.dumps(cve_data.__dict__, default=str),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            log.error(f"❌ Failed to store CVE data: {e}")

    async def get_relevant_cves(self, scan_params: Dict[str, Any]) -> Dict[str, Any]:
        """Get CVEs relevant to the target being scanned"""
        try:
            relevant_cves = []
            
            # Extract technology indicators from scan parameters
            target_url = scan_params.get('target_url', '')
            postman_data = scan_params.get('postman_collection', {})
            
            # Identify potential technologies from URL and collection
            technologies = self._identify_technologies(target_url, postman_data)
            
            # Query local database for relevant CVEs
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent high-severity CVEs
            cursor.execute('''
                SELECT * FROM cves 
                WHERE severity IN ('CRITICAL', 'HIGH')
                AND published_date >= date('now', '-30 days')
                ORDER BY cvss_v3_score DESC
                LIMIT 100
            ''')
            
            recent_cves = cursor.fetchall()
            
            # Get CVEs matching identified technologies
            tech_cves = []
            for tech in technologies:
                cursor.execute('''
                    SELECT * FROM cves 
                    WHERE (description LIKE ? OR cpe_matches LIKE ?)
                    AND severity IN ('CRITICAL', 'HIGH', 'MEDIUM')
                    ORDER BY cvss_v3_score DESC
                    LIMIT 20
                ''', (f'%{tech}%', f'%{tech}%'))
                
                tech_cves.extend(cursor.fetchall())
            
            conn.close()
            
            # Combine and deduplicate
            all_cves = {}
            for cve_row in recent_cves + tech_cves:
                cve_id = cve_row[0]  # First column is cve_id
                if cve_id not in all_cves:
                    all_cves[cve_id] = self._row_to_dict(cve_row)
            
            # Rank CVEs by relevance
            ranked_cves = self._rank_cves_by_relevance(
                list(all_cves.values()),
                technologies,
                scan_params
            )
            
            return {
                "status": "success",
                "total_cves": len(ranked_cves),
                "technologies_identified": technologies,
                "high_priority_cves": ranked_cves[:20],  # Top 20
                "cve_summary": {
                    "critical": len([c for c in ranked_cves if c['severity'] == 'CRITICAL']),
                    "high": len([c for c in ranked_cves if c['severity'] == 'HIGH']),
                    "medium": len([c for c in ranked_cves if c['severity'] == 'MEDIUM']),
                }
            }
            
        except Exception as e:
            log.error(f"❌ Failed to get relevant CVEs: {e}")
            return {"status": "error", "error": str(e)}

    def _identify_technologies(self, target_url: str, postman_data: Dict[str, Any]) -> List[str]:
        """Identify technologies from URL and Postman collection"""
        technologies = set()
        
        # Analyze URL
        url_lower = target_url.lower()
        tech_patterns = {
            'nodejs': ['node', 'express'],
            'python': ['python', 'django', 'flask'],
            'java': ['java', 'tomcat', 'spring'],
            'php': ['php'],
            'ruby': ['ruby', 'rails'],
            'dotnet': ['.net', 'aspnet', 'iis'],
            'apache': ['apache'],
            'nginx': ['nginx'],
            'mysql': ['mysql'],
            'postgresql': ['postgres'],
            'mongodb': ['mongo'],
            'redis': ['redis'],
            'elasticsearch': ['elastic'],
            'docker': ['docker'],
            'kubernetes': ['k8s', 'kube'],
            'aws': ['aws', 'amazon'],
            'azure': ['azure', 'microsoft'],
            'gcp': ['gcp', 'google']
        }
        
        for tech, patterns in tech_patterns.items():
            if any(pattern in url_lower for pattern in patterns):
                technologies.add(tech)
        
        # Analyze Postman collection headers and responses
        if postman_data:
            collection_str = json.dumps(postman_data).lower()
            for tech, patterns in tech_patterns.items():
                if any(pattern in collection_str for pattern in patterns):
                    technologies.add(tech)
        
        # Add generic API technologies
        technologies.update(['api', 'rest', 'json', 'http'])
        
        return list(technologies)

    def _rank_cves_by_relevance(self, cves: List[Dict[str, Any]], technologies: List[str], scan_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Rank CVEs by relevance to the target"""
        scored_cves = []
        
        for cve in cves:
            score = 0
            
            # Base score from CVSS
            cvss_score = cve.get('cvss_v3_score', 0)
            score += cvss_score * 10  # Weight CVSS heavily
            
            # Bonus for recent CVEs
            pub_date = datetime.fromisoformat(cve.get('published_date', ''))
            days_old = (datetime.now() - pub_date.replace(tzinfo=None)).days
            if days_old <= 30:
                score += 50
            elif days_old <= 90:
                score += 25
            
            # Bonus for technology matches
            description = cve.get('description', '').lower()
            cpe_matches = ' '.join(json.loads(cve.get('cpe_matches', '[]'))).lower()
            
            for tech in technologies:
                if tech in description or tech in cpe_matches:
                    score += 30
            
            # Bonus for common API vulnerabilities
            api_keywords = ['authentication', 'authorization', 'injection', 'cors', 'csrf', 'xss']
            for keyword in api_keywords:
                if keyword in description:
                    score += 20
            
            # Penalty for low exploitability
            exploitability = cve.get('exploitability_score', 0)
            if exploitability and exploitability < 2.0:
                score -= 10
            
            cve['relevance_score'] = score
            scored_cves.append(cve)
        
        # Sort by relevance score
        return sorted(scored_cves, key=lambda x: x['relevance_score'], reverse=True)

    def _row_to_dict(self, row) -> Dict[str, Any]:
        """Convert database row to dictionary"""
        columns = [
            'cve_id', 'description', 'cvss_v3_score', 'cvss_v2_score', 'severity',
            'published_date', 'last_modified', 'cwe_ids', 'cpe_matches', 'references',
            'exploitability_score', 'impact_score', 'attack_vector', 'attack_complexity',
            'privileges_required', 'user_interaction', 'scope',
            'confidentiality_impact', 'integrity_impact', 'availability_impact',
            'raw_data', 'created_at'
        ]
        
        result = {}
        for i, value in enumerate(row):
            if i < len(columns):
                column = columns[i]
                if column in ['cwe_ids', 'cpe_matches', 'references']:
                    try:
                        result[column] = json.loads(value) if value else []
                    except:
                        result[column] = []
                else:
                    result[column] = value
        
        return result

    async def search_cves(self, keyword: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Search CVEs by keyword"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM cves 
                WHERE description LIKE ? OR cve_id LIKE ?
                ORDER BY cvss_v3_score DESC
                LIMIT ?
            ''', (f'%{keyword}%', f'%{keyword}%', limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            return [self._row_to_dict(row) for row in rows]
            
        except Exception as e:
            log.error(f"❌ CVE search failed: {e}")
            return []

    async def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information for a specific CVE"""
        try:
            # Try local database first
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE cve_id = ?', (cve_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return self._row_to_dict(row)
            
            # If not in local database, fetch from NVD API
            params = {"cveId": cve_id}
            data = await self._make_request(self.base_url, params)
            
            if data and 'vulnerabilities' in data and data['vulnerabilities']:
                cve_data = self._parse_cve_data(data['vulnerabilities'][0])
                if cve_data:
                    self._store_cve_data(cve_data)
                    return cve_data.__dict__
            
            return None
            
        except Exception as e:
            log.error(f"❌ Failed to get CVE details: {e}")
            return None

    async def get_trending_vulnerabilities(self, days: int = 7) -> Dict[str, Any]:
        """Get trending vulnerabilities from the last N days"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT severity, COUNT(*) as count, AVG(cvss_v3_score) as avg_score
                FROM cves 
                WHERE published_date >= date('now', '-{} days')
                GROUP BY severity
                ORDER BY count DESC
            '''.format(days))
            
            severity_trends = cursor.fetchall()
            
            cursor.execute('''
                SELECT cwe_ids, COUNT(*) as count
                FROM cves 
                WHERE published_date >= date('now', '-{} days')
                AND cwe_ids != '[]'
                GROUP BY cwe_ids
                ORDER BY count DESC
                LIMIT 10
            '''.format(days))
            
            cwe_trends = cursor.fetchall()
            
            cursor.execute('''
                SELECT * FROM cves 
                WHERE published_date >= date('now', '-{} days')
                ORDER BY cvss_v3_score DESC
                LIMIT 20
            '''.format(days))
            
            top_cves = cursor.fetchall()
            
            conn.close()
            
            return {
                "status": "success",
                "time_period_days": days,
                "severity_distribution": [
                    {"severity": row[0], "count": row[1], "avg_cvss": row[2]}
                    for row in severity_trends
                ],
                "top_cwe_patterns": [
                    {"cwe_ids": json.loads(row[0]) if row[0] else [], "count": row[1]}
                    for row in cwe_trends
                ],
                "highest_scoring_cves": [self._row_to_dict(row) for row in top_cves]
            }
            
        except Exception as e:
            log.error(f"❌ Failed to get trending vulnerabilities: {e}")
            return {"status": "error", "error": str(e)}

    def get_stats(self) -> Dict[str, Any]:
        """Get NVD integration statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total CVEs
            cursor.execute('SELECT COUNT(*) FROM cves')
            total_cves = cursor.fetchone()[0]
            
            # CVEs by severity
            cursor.execute('SELECT severity, COUNT(*) FROM cves GROUP BY severity')
            severity_counts = dict(cursor.fetchall())
            
            # Recent CVEs (last 30 days)
            cursor.execute('''
                SELECT COUNT(*) FROM cves 
                WHERE published_date >= date('now', '-30 days')
            ''')
            recent_cves = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                "total_cves_cached": total_cves,
                "severity_distribution": severity_counts,
                "recent_cves_30_days": recent_cves,
                "last_sync": self.last_sync.isoformat() if self.last_sync else None,
                "api_key_configured": bool(self.api_key),
                "rate_limit": self.rate_limit,
                "database_path": self.db_path
            }
            
        except Exception as e:
            log.error(f"❌ Failed to get NVD stats: {e}")
            return {"status": "error", "error": str(e)}

    async def __aenter__(self):
        """Async context manager entry"""
        if not self.session:
            self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
            self.session = None
