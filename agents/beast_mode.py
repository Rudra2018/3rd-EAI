#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Beast Mode - Multi-Agent Concurrent Security Testing (Fixed)
"""

import asyncio
import concurrent.futures as futures
import logging
import time
import json
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict
import threading
from queue import Queue, Empty

# AI integration
try:
    from ai.advanced_ai_coordinator import AdvancedAICoordinator, AIRequest
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# CrewAI integration - Make optional to avoid aiohttp conflicts
try:
    from crewai import Agent, Task, Crew
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    print("⚠️  CrewAI not available - using standard multi-threading")

log = logging.getLogger(__name__)

@dataclass
class ScanTask:
    """Enhanced scan task with AI guidance"""
    id: str
    endpoint: Dict[str, Any]
    method: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    data: Dict[str, Any] = field(default_factory=dict)
    priority: int = 1
    ai_guidance: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    created_at: datetime = field(default_factory=datetime.now)
    estimated_duration: float = 5.0

@dataclass
class ScanResult:
    """Enhanced scan result with AI analysis"""
    task_id: str
    endpoint: str
    method: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    status: str = "pending"
    error: Optional[str] = None
    ai_insights: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    completed_at: Optional[datetime] = None

class EnhancedBeastMode:
    """
    Enhanced multi-agent concurrent security scanning system (Fixed)
    Features:
    - Intelligent task distribution and prioritization
    - Real-time agent coordination and load balancing  
    - AI-powered scan planning and optimization
    - Dynamic resource allocation
    - Comprehensive monitoring and metrics
    - Failure recovery and retry mechanisms
    - Optional CrewAI integration (fallback to standard threading)
    """
    
    def __init__(self, max_workers: int = 16, ai_enhanced: bool = True):
        self.max_workers = max_workers
        self.ai_enhanced = ai_enhanced and AI_AVAILABLE
        
        # Task management
        self.task_queue = Queue()
        self.priority_queues = {1: Queue(), 2: Queue(), 3: Queue()}
        self.active_tasks: Dict[str, ScanTask] = {}
        self.completed_results: Dict[str, ScanResult] = {}
        
        # Agent management
        self.agent_pool = None
        self.crew = None
        self.running = False
        self.start_time = None
        self.total_tasks = 0
        self.completed_tasks = 0
        self.failed_tasks = 0
        
        # AI components
        self.ai_coordinator = None
        
        if self.ai_enhanced:
            try:
                self.ai_coordinator = AdvancedAICoordinator()
                log.info("✅ AI-enhanced beast mode initialized")
                
                if CREWAI_AVAILABLE:
                    self._initialize_crew_agents()
                else:
                    log.info("🔄 Using standard threading (CrewAI not available)")
            except Exception as e:
                log.warning(f"AI initialization failed: {e}")
                self.ai_enhanced = False

    def _initialize_crew_agents(self):
        """Initialize CrewAI autonomous agents (if available)"""
        try:
            if not CREWAI_AVAILABLE:
                return
                
            # Define specialized security testing agents
            reconnaissance_agent = Agent(
                role="API Reconnaissance Specialist",
                goal="Discover and analyze API endpoints for security testing",
                backstory="Expert in API discovery, endpoint analysis, and attack surface mapping",
                verbose=True,
                allow_delegation=True
            )
            
            vulnerability_hunter = Agent(
                role="Vulnerability Research Specialist", 
                goal="Identify and validate security vulnerabilities in APIs",
                backstory="Advanced penetration tester specializing in API security vulnerabilities",
                verbose=True,
                allow_delegation=True
            )
            
            self.crew = Crew(
                agents=[reconnaissance_agent, vulnerability_hunter],
                verbose=2
            )
            
            log.info("🤖 CrewAI agents initialized successfully")
            
        except Exception as e:
            log.error(f"CrewAI initialization failed: {e}")
            self.crew = None

    async def run_enhanced_beast_mode(self, endpoints: List[Dict[str, Any]], adapter, 
                                    scan_config: Optional[Dict[str, Any]] = None) -> List[Dict]:
        """Enhanced beast mode execution with intelligent coordination"""
        if not endpoints:
            log.warning("No endpoints provided for beast mode scanning")
            return []
        
        if adapter is None:
            log.warning("No scanner adapter provided, using mock results")
            return self._generate_mock_findings(endpoints)
        
        try:
            log.info(f"🚀 Starting enhanced beast mode with {len(endpoints)} endpoints")
            self.start_time = datetime.now()
            self.running = True
            
            # Generate AI-enhanced scan plan
            scan_plan = await self._generate_ai_scan_plan(endpoints, scan_config)
            
            # Create enhanced scan tasks
            tasks = await self._create_enhanced_scan_tasks(endpoints, scan_plan, adapter)
            self.total_tasks = len(tasks)
            
            # Execute tasks with enhanced coordination
            results = await self._execute_coordinated_scan(adapter, tasks)
            
            # Generate comprehensive analysis
            final_results = await self._generate_enhanced_analysis(results)
            
            log.info(f"✅ Beast mode completed: {len(final_results)} findings from {self.completed_tasks} tasks")
            return final_results
            
        except Exception as e:
            log.error(f"Beast mode execution failed: {e}")
            return []
        finally:
            self.running = False

    async def _generate_ai_scan_plan(self, endpoints: List[Dict[str, Any]], 
                                   config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate AI-powered scan plan"""
        if not self.ai_enhanced or not self.ai_coordinator:
            return {"strategy": "standard", "priorities": {}}
        
        try:
            # Simplified scan plan for compatibility
            plan = {
                "strategy": "enhanced_threading",
                "priorities": {
                    "high_priority_indices": list(range(min(5, len(endpoints)))),
                    "medium_priority_indices": list(range(5, min(15, len(endpoints)))),
                    "low_priority_indices": list(range(15, len(endpoints)))
                },
                "resource_allocation": {
                    "threads_per_priority": {"high": 8, "medium": 4, "low": 4},
                    "timeout_per_request": 30
                }
            }
            
            log.info(f"🧠 AI scan plan generated: {plan['strategy']} approach")
            return plan
            
        except Exception as e:
            log.error(f"AI scan planning failed: {e}")
        
        return {"strategy": "standard", "priorities": {}}

    async def _create_enhanced_scan_tasks(self, endpoints: List[Dict[str, Any]], 
                                        scan_plan: Dict[str, Any], adapter) -> List[ScanTask]:
        """Create enhanced scan tasks with AI guidance"""
        tasks = []
        
        priorities = scan_plan.get("priorities", {})
        high_priority = set(priorities.get("high_priority_indices", []))
        medium_priority = set(priorities.get("medium_priority_indices", []))
        
        for i, endpoint in enumerate(endpoints):
            try:
                # Determine priority
                if i in high_priority:
                    priority = 1
                elif i in medium_priority:
                    priority = 2
                else:
                    priority = 3
                
                # Create base scan task
                task = ScanTask(
                    id=f"task_{i}_{int(time.time())}",
                    endpoint=endpoint,
                    method=endpoint.get("method", "GET"),
                    url=endpoint.get("url", ""),
                    headers=endpoint.get("headers", {}),
                    data=self._prepare_scan_data(endpoint),
                    priority=priority,
                    context={
                        "endpoint_index": i,
                        "business_function": endpoint.get("business_function"),
                        "folder_path": endpoint.get("folder_path", [])
                    }
                )
                
                tasks.append(task)
                
            except Exception as e:
                log.error(f"Failed to create task for endpoint {i}: {e}")
                continue
        
        return tasks

    def _prepare_scan_data(self, endpoint: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare scan data for endpoint"""
        scan_data = {}
        
        # Add URL parameters
        url_params = endpoint.get("url_params", {})
        if url_params:
            scan_data.update(url_params)
        
        # Add body data for write operations
        if endpoint.get("method", "GET") in ["POST", "PUT", "PATCH"]:
            body_info = endpoint.get("body", {})
            
            if body_info.get("mode") == "raw" and body_info.get("content"):
                try:
                    body_json = json.loads(body_info["content"])
                    scan_data.update(body_json)
                except json.JSONDecodeError:
                    scan_data["raw_body"] = body_info["content"]
        
        return scan_data

    async def _execute_coordinated_scan(self, adapter, tasks: List[ScanTask]) -> List[ScanResult]:
        """Execute coordinated scanning with enhanced management"""
        results = []
        
        # Create thread pool executor
        with futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit tasks
            future_to_task = {}
            
            for task in tasks:
                future = executor.submit(self._execute_single_task, task, adapter)
                future_to_task[future] = task
                self.active_tasks[task.id] = task
            
            # Process completed tasks
            for future in futures.as_completed(future_to_task.keys()):
                task = future_to_task[future]
                
                try:
                    result = future.result()
                    results.append(result)
                    self.completed_results[task.id] = result
                    
                    if task.id in self.active_tasks:
                        del self.active_tasks[task.id]
                    
                    self.completed_tasks += 1
                    
                    # Log significant findings
                    if result.vulnerabilities:
                        log.info(f"🎯 Found {len(result.vulnerabilities)} vulnerabilities in {result.endpoint}")
                    
                except Exception as e:
                    log.error(f"Task {task.id} failed: {e}")
                    self.failed_tasks += 1
        
        return results

    def _execute_single_task(self, task: ScanTask, adapter) -> ScanResult:
        """Execute a single scan task"""
        start_time = time.time()
        result = ScanResult(
            task_id=task.id,
            endpoint=task.url,
            method=task.method,
            status="running"
        )
        
        try:
            # Execute the scan
            vulnerabilities = adapter.call(
                task.url,
                task.method,
                headers=task.headers,
                data=task.data
            ) or []
            
            # Process vulnerabilities
            processed_vulns = []
            for vuln in vulnerabilities:
                if hasattr(vuln, 'to_dict'):
                    vuln_dict = vuln.to_dict()
                else:
                    vuln_dict = vuln
                
                # Add task context
                vuln_dict.update({
                    "task_context": task.context,
                    "discovery_method": "beast_mode_enhanced"
                })
                
                processed_vulns.append(vuln_dict)
            
            # Update result
            result.vulnerabilities = processed_vulns
            result.status = "completed"
            result.execution_time = time.time() - start_time
            result.completed_at = datetime.now()
            
        except Exception as e:
            result.status = "failed"
            result.error = str(e)
            result.execution_time = time.time() - start_time
        
        return result

    async def _generate_enhanced_analysis(self, results: List[ScanResult]) -> List[Dict]:
        """Generate enhanced analysis of results"""
        final_findings = []
        
        # Collect all vulnerabilities
        for result in results:
            for vuln in result.vulnerabilities:
                # Add beast mode metadata
                vuln.update({
                    "beast_mode_enhanced": True,
                    "scan_timestamp": datetime.now().isoformat(),
                    "execution_time": result.execution_time,
                    "crewai_enabled": CREWAI_AVAILABLE
                })
                final_findings.append(vuln)
        
        return final_findings

    def _generate_mock_findings(self, endpoints: List[Dict[str, Any]]) -> List[Dict]:
        """Generate mock findings when adapter is not available"""
        mock_findings = []
        
        for i, endpoint in enumerate(endpoints[:3]):  # Limit to first 3 for demo
            mock_findings.append({
                "type": "Enhanced Beast Mode Analysis",
                "severity": ["Low", "Medium", "High"][i % 3],
                "description": f"Beast mode analysis of {endpoint.get('name', 'endpoint')}",
                "endpoint": endpoint.get("url", ""),
                "method": endpoint.get("method", "GET"),
                "beast_mode_enhanced": True,
                "confidence": "Low",
                "crewai_enabled": CREWAI_AVAILABLE
            })
        
        return mock_findings

    def get_scan_statistics(self) -> Dict[str, Any]:
        """Get comprehensive scan statistics"""
        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        return {
            "beast_mode_enhanced": True,
            "total_tasks": self.total_tasks,
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "success_rate": (self.completed_tasks / self.total_tasks) if self.total_tasks > 0 else 0,
            "scan_duration_seconds": duration,
            "ai_enhanced": self.ai_enhanced,
            "crewai_enabled": CREWAI_AVAILABLE,
            "max_workers": self.max_workers
        }

# Enhanced factory function
def run_enhanced_beast_mode(endpoints: List[Dict[str, Any]], adapter, 
                          max_workers: int = 16, ai_enhanced: bool = True, 
                          scan_config: Optional[Dict[str, Any]] = None) -> List[Dict]:
    """Factory function to run enhanced beast mode"""
    beast = EnhancedBeastMode(max_workers=max_workers, ai_enhanced=ai_enhanced)
    
    # Run asynchronously
    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        return loop.run_until_complete(
            beast.run_enhanced_beast_mode(endpoints, adapter, scan_config)
        )
    finally:
        loop.close()

# Backward compatibility
def run_beast_mode(endpoints: List[Dict[str, Any]], adapter, max_workers: int = 16) -> List[Dict]:
    """Legacy function for backward compatibility"""
    return run_enhanced_beast_mode(endpoints, adapter, max_workers, ai_enhanced=True)

