import asyncio
import logging
import json
import os
from typing import List, Dict, Any, Optional, Set
import aiohttp
from datetime import datetime

# Import existing integrations
try:
    from api_scanner.integrations.projectdiscovery_chaos import ChaosClient, ChaosNotFound
    CHAOS_AVAILABLE = True
except ImportError:
    CHAOS_AVAILABLE = False

try:
    from api_scanner.integrations.hackerone_api import HackerOneAPI
    HACKERONE_PRIVATE_AVAILABLE = True
except ImportError:
    HACKERONE_PRIVATE_AVAILABLE = False

log = logging.getLogger("program-sources")

class ProgramSource:
    """Base class for bug bounty program sources."""
    
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        raise NotImplementedError

class HackerOnePrivateSource(ProgramSource):
    """Fetch private programs from HackerOne API with authentication."""
    
    def __init__(self, username: str, api_token: str):
        self.username = username
        self.api_token = api_token
        self.base_url = "https://api.hackerone.com/v1"
        self.auth = aiohttp.BasicAuth(login=username, password=api_token)
        
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        """Fetch private HackerOne programs with structured scopes."""
        programs = []
        
        try:
            async with aiohttp.ClientSession(
                auth=self.auth,
                timeout=aiohttp.ClientTimeout(total=30)
            ) as session:
                
                # First, get list of programs the user has access to
                programs_url = f"{self.base_url}/hackers/programs"
                
                async with session.get(programs_url) as resp:
                    if resp.status == 401:
                        log.error("HackerOne authentication failed - check credentials")
                        return []
                    elif resp.status != 200:
                        log.error(f"HackerOne API error: {resp.status}")
                        return []
                    
                    data = await resp.json()
                    program_handles = []
                    
                    for program in data.get("data", []):
                        handle = program.get("attributes", {}).get("handle")
                        if handle:
                            program_handles.append({
                                "handle": handle,
                                "name": program.get("attributes", {}).get("name", handle),
                                "state": program.get("attributes", {}).get("state", "unknown")
                            })
                
                log.info(f"Found {len(program_handles)} accessible HackerOne programs")
                
                # Now fetch structured scopes for each program
                for program_info in program_handles[:20]:  # Limit to avoid rate limits
                    handle = program_info["handle"]
                    
                    try:
                        scopes_url = f"{self.base_url}/hackers/programs/{handle}/structured_scopes"
                        
                        async with session.get(scopes_url) as scope_resp:
                            if scope_resp.status == 200:
                                scope_data = await scope_resp.json()
                                
                                # Extract API-related scopes
                                api_scopes = []
                                for scope in scope_data.get("data", []):
                                    attributes = scope.get("attributes", {})
                                    asset_identifier = attributes.get("asset_identifier", "")
                                    asset_type = attributes.get("asset_type", "")
                                    eligible_for_submission = attributes.get("eligible_for_submission", False)
                                    
                                    if (eligible_for_submission and 
                                        asset_type in ["URL", "CIDR", "WILDCARD"] and
                                        ("api" in asset_identifier.lower() or 
                                         "graphql" in asset_identifier.lower() or
                                         asset_identifier.startswith("*."))):
                                        api_scopes.append(asset_identifier)
                                
                                if api_scopes:
                                    programs.append({
                                        "name": program_info["name"],
                                        "handle": handle,
                                        "scope": api_scopes,
                                        "source": "hackerone_private",
                                        "state": program_info["state"],
                                        "url": f"https://hackerone.com/{handle}"
                                    })
                                    
                            await asyncio.sleep(0.5)  # Rate limiting
                            
                    except Exception as e:
                        log.warning(f"Failed to fetch scopes for {handle}: {e}")
                        continue
                        
        except Exception as e:
            log.error(f"HackerOne private API failed: {e}")
            
        log.info(f"Fetched {len(programs)} private HackerOne programs with API scopes")
        return programs

class HackerOnePublicSource(ProgramSource):
    """Fetch public programs from HackerOne directory."""
    
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        """Fetch well-known public HackerOne programs."""
        return [
            {
                "name": "Shopify",
                "scope": ["*.shopify.com", "api.shopify.com", "partners.shopify.com"],
                "source": "hackerone_public",
                "url": "https://hackerone.com/shopify"
            },
            {
                "name": "GitHub",  
                "scope": ["api.github.com", "*.github.com", "github.com/api/*"],
                "source": "hackerone_public",
                "url": "https://hackerone.com/github"
            },
            {
                "name": "GitLab",
                "scope": ["gitlab.com/api/*", "*.gitlab.com", "api.gitlab.com"],
                "source": "hackerone_public",
                "url": "https://hackerone.com/gitlab"
            },
            {
                "name": "Slack",
                "scope": ["*.slack.com", "api.slack.com", "hooks.slack.com"],
                "source": "hackerone_public"
            }
        ]

class BugCrowdSource(ProgramSource):
    """Enhanced Bugcrowd source with more programs."""
    
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Tesla",
                "scope": ["*.tesla.com", "api.tesla.com", "owner-api.teslamotors.com"],
                "source": "bugcrowd"
            },
            {
                "name": "Dropbox",
                "scope": ["*.dropbox.com", "api.dropboxapi.com", "content.dropboxapi.com"],
                "source": "bugcrowd"
            },
            {
                "name": "Western Union",
                "scope": ["*.westernunion.com", "api.westernunion.com"],
                "source": "bugcrowd"
            },
            {
                "name": "Coinbase",
                "scope": ["*.coinbase.com", "api.coinbase.com", "api.pro.coinbase.com"],
                "source": "bugcrowd"
            }
        ]

class IntigritiSource(ProgramSource):
    """Enhanced Intigriti source."""
    
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "European Central Bank",
                "scope": ["*.ecb.europa.eu", "api.ecb.europa.eu"],
                "source": "intigriti"
            },
            {
                "name": "Nokia",
                "scope": ["*.nokia.com", "api.nokia.com", "developer.nokia.com"],
                "source": "intigriti"
            },
            {
                "name": "Atos",
                "scope": ["*.atos.net", "api.atos.net"],
                "source": "intigriti"
            }
        ]

class YesWeHackSource(ProgramSource):
    """Enhanced YesWeHack source."""
    
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Orange",
                "scope": ["*.orange.com", "api.orange.com", "developer.orange.com"],
                "source": "yeswehack"
            },
            {
                "name": "Deezer",
                "scope": ["*.deezer.com", "api.deezer.com"],
                "source": "yeswehack"
            },
            {
                "name": "OVH",
                "scope": ["*.ovh.com", "api.ovh.com", "*.ovhcloud.com"],
                "source": "yeswehack"
            }
        ]

class ChaosSource(ProgramSource):
    """Fetch subdomains from Chaos API for enhanced scope discovery."""
    
    def __init__(self, api_token: str):
        self.api_token = api_token
        
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        """Use Chaos to discover subdomains for popular domains."""
        if not CHAOS_AVAILABLE:
            log.warning("Chaos client not available")
            return []
            
        programs = []
        
        try:
            chaos_client = ChaosClient(api_token=self.api_token)
            
            # Popular domains to scan for API subdomains
            target_domains = [
                "shopify.com", "github.com", "gitlab.com", "slack.com",
                "tesla.com", "dropbox.com", "coinbase.com", "stripe.com"
            ]
            
            for domain in target_domains:
                try:
                    subdomains = chaos_client.get_subdomains(domain)
                    api_subdomains = [
                        sub for sub in subdomains 
                        if any(indicator in sub.lower() for indicator in ["api", "rest", "graphql", "v1", "v2", "dev"])
                    ]
                    
                    if api_subdomains:
                        programs.append({
                            "name": f"{domain.title()} (Chaos Discovery)",
                            "scope": list(api_subdomains)[:10],  # Limit to avoid too many
                            "source": "chaos",
                            "discovered_count": len(subdomains),
                            "api_count": len(api_subdomains)
                        })
                        
                except ChaosNotFound:
                    log.debug(f"No Chaos data for {domain}")
                except Exception as e:
                    log.warning(f"Chaos error for {domain}: {e}")
                    
        except Exception as e:
            log.error(f"Chaos source failed: {e}")
            
        log.info(f"Chaos discovered {len(programs)} programs")
        return programs

class WeaknessSource(ProgramSource):
    """Source for known vulnerable/interesting endpoints from various sources."""
    
    async def fetch_programs(self) -> List[Dict[str, Any]]:
        """Return known interesting API endpoints for testing."""
        return [
            {
                "name": "Common API Testing Endpoints",
                "scope": [
                    "https://jsonplaceholder.typicode.com",
                    "https://httpbin.org",
                    "https://reqres.in/api",
                    "https://gorest.co.in/public/v2"
                ],
                "source": "testing_endpoints",
                "description": "Safe endpoints for testing scanner functionality"
            },
            {
                "name": "GraphQL Common Endpoints",
                "scope": [
                    "https://api.github.com/graphql",
                    "https://shopify.dev/graphql-admin-api",
                    "https://api.spacex.land/graphql"
                ],
                "source": "graphql_endpoints",
                "description": "Common GraphQL endpoints"
            }
        ]

class ProgramAggregator:
    """Enhanced aggregator supporting multiple sources including private APIs."""
    
    def __init__(self):
        self.sources = []
        
        # Always add public sources
        self.sources.extend([
            HackerOnePublicSource(),
            BugCrowdSource(),
            IntigritiSource(),
            YesWeHackSource(),
            WeaknessSource()
        ])
        
        # Add private HackerOne if credentials available
        h1_username = os.getenv("HACKERONE_USERNAME")
        h1_token = os.getenv("HACKERONE_API_TOKEN")
        if h1_username and h1_token:
            self.sources.append(HackerOnePrivateSource(h1_username, h1_token))
            log.info("Added HackerOne private API source")
        
        # Add Chaos if token available
        chaos_token = os.getenv("CHAOS_API_TOKEN")
        if chaos_token and CHAOS_AVAILABLE:
            self.sources.append(ChaosSource(chaos_token))
            log.info("Added Chaos API source")
    
    async def get_all_programs(self) -> List[Dict[str, Any]]:
        """Fetch programs from all available sources concurrently."""
        all_programs = []
        
        tasks = []
        for source in self.sources:
            tasks.append(self._fetch_with_timeout(source))
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for i, result in enumerate(results):
                source_name = self.sources[i].__class__.__name__
                if isinstance(result, Exception):
                    log.error(f"Source {source_name} failed: {result}")
                else:
                    all_programs.extend(result)
                    log.info(f"Source {source_name} contributed {len(result)} programs")
        
        except Exception as e:
            log.error(f"Program aggregation failed: {e}")
        
        log.info(f"Total programs aggregated: {len(all_programs)} from {len(self.sources)} sources")
        return all_programs
    
    async def _fetch_with_timeout(self, source: ProgramSource, timeout: int = 60) -> List[Dict[str, Any]]:
        """Fetch programs with timeout protection."""
        try:
            return await asyncio.wait_for(source.fetch_programs(), timeout=timeout)
        except asyncio.TimeoutError:
            log.warning(f"Source {source.__class__.__name__} timed out after {timeout}s")
            return []
    
    def extract_api_endpoints(self, programs: List[Dict[str, Any]], max_per_program: int = 10) -> List[Dict[str, Any]]:
        """Extract and normalize API endpoints with metadata."""
        api_targets = []
        
        for program in programs:
            scope = program.get("scope", [])
            program_name = program.get("name", "unknown")
            source = program.get("source", "unknown")
            
            program_urls = []
            
            for item in scope:
                if self._is_api_endpoint(item):
                    normalized_urls = self._normalize_scope_item(item)
                    for url in normalized_urls[:max_per_program]:  # Limit per program
                        program_urls.append({
                            "url": url,
                            "program": program_name,
                            "source": source,
                            "original_scope": item
                        })
            
            api_targets.extend(program_urls)
        
        # Deduplicate by URL
        unique_targets = []
        seen_urls = set()
        
        for target in api_targets:
            url = target["url"]
            if url not in seen_urls:
                unique_targets.append(target)
                seen_urls.add(url)
        
        log.info(f"Extracted {len(unique_targets)} unique API endpoints from {len(programs)} programs")
        return unique_targets
    
    def _is_api_endpoint(self, scope_item: str) -> bool:
        """Enhanced API endpoint detection."""
        api_indicators = [
            "api.", "rest.", "graphql.", "v1.", "v2.", "v3.", "v4.",
            "/api/", "/rest/", "/graphql/", "/v1/", "/v2/",
            ".json", ".xml", "developer.", "docs.", "webhook",
            "oauth", "auth.", "login.", "admin."
        ]
        return any(indicator in scope_item.lower() for indicator in api_indicators)
    
    def _normalize_scope_item(self, item: str) -> List[str]:
        """Enhanced scope normalization with better URL generation."""
        urls = []
        item = item.strip()
        
        # Handle wildcard domains
        if "*." in item:
            base_domain = item.replace("*.", "")
            api_patterns = [
                f"https://api.{base_domain}",
                f"https://api.{base_domain}/v1",
                f"https://api.{base_domain}/v2",
                f"https://rest.{base_domain}",
                f"https://graphql.{base_domain}",
                f"https://developer.{base_domain}",
                f"https://oauth.{base_domain}",
                f"https://auth.{base_domain}"
            ]
            urls.extend(api_patterns)
            
        # Handle direct API endpoints
        elif any(indicator in item.lower() for indicator in ["api.", "graphql.", "rest.", "developer."]):
            if not item.startswith("http"):
                urls.append(f"https://{item}")
            else:
                urls.append(item)
                
        # Handle path-based scopes
        elif "/" in item and not item.startswith("http"):
            base_url = f"https://{item.replace('/*', '').rstrip('/')}"
            urls.append(base_url)
            
        # Handle domain with common API paths
        elif "." in item and not item.startswith("http"):
            base_domain = item
            common_paths = [
                f"https://{base_domain}/api",
                f"https://{base_domain}/api/v1",
                f"https://{base_domain}/api/v2",
                f"https://{base_domain}/graphql",
                f"https://{base_domain}/rest"
            ]
            urls.extend(common_paths)
        
        return urls

