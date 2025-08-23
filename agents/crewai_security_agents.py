#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CrewAI Security Agents for Autonomous API Security Testing
Multi-agent system for comprehensive security assessment
"""

import os
import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

try:
    from crewai import Agent, Task, Crew, Process
    from crewai.flow.flow import Flow, listen, start, router
    from langchain_openai import ChatOpenAI
    from langchain_google_genai import ChatGoogleGenerativeAI
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False
    
log = logging.getLogger(__name__)

class SecurityDomain(Enum):
    API_RECONNAISSANCE = "api_reconnaissance"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    EXPLOIT_DEVELOPMENT = "exploit_development"
    THREAT_INTELLIGENCE = "threat_intelligence"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    RISK_ANALYSIS = "risk_analysis"

@dataclass
class SecurityAssessmentRequest:
    target_info: Dict[str, Any]
    assessment_scope: List[str]
    priority_level: str = "medium"
    compliance_frameworks: List[str] = None
    custom_requirements: Dict[str, Any] = None

class CrewAISecurityAgents:
    """
    Advanced multi-agent security testing system using CrewAI
    Features:
    - Specialized security agents for different domains
    - Autonomous decision-making and task delegation
    - Collaborative intelligence between agents
    - Real-time learning and adaptation
    """
    
    def __init__(self):
        self.initialized = False
        self.agents = {}
        self.crews = {}
        self.llm = None
        
        if CREWAI_AVAILABLE:
            self.initialize_llm()
            self.create_security_agents()
            self.create_specialized_crews()
            self.initialized = True
            log.info("✅ CrewAI Security Agents initialized successfully")
        else:
            log.warning("⚠️ CrewAI not available - falling back to basic mode")

    def initialize_llm(self):
        """Initialize LLM for CrewAI agents"""
        try:
            # Try OpenAI first
            if os.getenv("OPENAI_API_KEY"):
                self.llm = ChatOpenAI(
                    model="gpt-4o-mini",
                    temperature=0.3,
                    api_key=os.getenv("OPENAI_API_KEY")
                )
                log.info("🤖 Using OpenAI for CrewAI agents")
            # Fallback to Gemini
            elif os.getenv("GOOGLE_API_KEY"):
                self.llm = ChatGoogleGenerativeAI(
                    model="gemini-1.5-flash",
                    temperature=0.3,
                    google_api_key=os.getenv("GOOGLE_API_KEY")
                )
                log.info("🤖 Using Gemini for CrewAI agents")
            else:
                log.error("❌ No API keys available for CrewAI LLM")
                self.llm = None
        except Exception as e:
            log.error(f"❌ Failed to initialize LLM: {e}")
            self.llm = None

    def create_security_agents(self):
        """Create specialized security agents"""
        if not self.llm:
            return
            
        # API Reconnaissance Agent
        self.agents["reconnaissance"] = Agent(
            role="Senior API Security Reconnaissance Specialist",
            goal="Discover and map API attack surfaces, identify hidden endpoints, and gather intelligence",
            backstory="""You are an elite cybersecurity expert with 15 years of experience in API security assessment. 
            You excel at discovering hidden APIs, analyzing API documentation, and identifying potential attack vectors. 
            Your systematic approach to reconnaissance has uncovered critical vulnerabilities in Fortune 500 companies.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=True,
            max_execution_time=300
        )

        # Vulnerability Discovery Agent  
        self.agents["vulnerability_hunter"] = Agent(
            role="Advanced Vulnerability Research Specialist",
            goal="Identify complex security vulnerabilities using advanced testing techniques",
            backstory="""You are a world-class vulnerability researcher known for discovering zero-day vulnerabilities. 
            You combine automated testing with creative manual techniques to find vulnerabilities others miss. 
            Your discoveries have been featured in major security advisories and earned significant bug bounties.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=True,
            max_execution_time=600
        )

        # Exploit Development Agent
        self.agents["exploit_developer"] = Agent(
            role="Senior Exploit Development Engineer", 
            goal="Develop proof-of-concept exploits and assess vulnerability impact",
            backstory="""You are an expert exploit developer with deep knowledge of vulnerability exploitation techniques. 
            You create reliable, educational proof-of-concept exploits that demonstrate real-world impact. 
            Your work helps organizations understand true risk and prioritize remediation efforts.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_execution_time=400
        )

        # Threat Intelligence Agent
        self.agents["threat_intel"] = Agent(
            role="Senior Threat Intelligence Analyst",
            goal="Provide contextual threat intelligence and attack pattern analysis",
            backstory="""You are a strategic threat intelligence analyst with access to global threat data. 
            You analyze attack patterns, correlate threat actor behaviors, and provide actionable intelligence 
            that helps organizations defend against targeted attacks.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=True,
            max_execution_time=300
        )

        # Compliance Assessment Agent
        self.agents["compliance"] = Agent(
            role="Security Compliance and Risk Assessment Expert",
            goal="Assess compliance posture and map findings to regulatory frameworks",
            backstory="""You are a senior compliance expert with deep knowledge of security frameworks like NIST, 
            ISO 27001, PCI DSS, and SOC 2. You translate technical findings into business risk and compliance impact, 
            helping organizations meet their regulatory obligations.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False,
            max_execution_time=200
        )

        # Risk Analysis Agent
        self.agents["risk_analyst"] = Agent(
            role="Senior Cybersecurity Risk Analyst",
            goal="Analyze and prioritize security risks based on business impact",
            backstory="""You are a strategic risk analyst who translates technical vulnerabilities into business language. 
            You excel at risk quantification, impact assessment, and creating actionable remediation roadmaps that 
            align with business priorities and resource constraints.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=True,
            max_execution_time=250
        )

    def create_specialized_crews(self):
        """Create specialized crews for different assessment types"""
        if not self.agents:
            return

        # Comprehensive API Security Assessment Crew
        self.crews["comprehensive"] = Crew(
            agents=[
                self.agents["reconnaissance"],
                self.agents["vulnerability_hunter"], 
                self.agents["exploit_developer"],
                self.agents["threat_intel"],
                self.agents["risk_analyst"]
            ],
            process=Process.sequential,
            verbose=True,
            memory=True,
            cache=True,
            max_execution_time=1800  # 30 minutes
        )

        # Quick Security Scan Crew  
        self.crews["quick_scan"] = Crew(
            agents=[
                self.agents["vulnerability_hunter"],
                self.agents["risk_analyst"]
            ],
            process=Process.sequential,
            verbose=True,
            memory=True,
            max_execution_time=600  # 10 minutes
        )

        # Compliance Assessment Crew
        self.crews["compliance"] = Crew(
            agents=[
                self.agents["reconnaissance"],
                self.agents["compliance"],
                self.agents["risk_analyst"]
            ],
            process=Process.sequential,
            verbose=True,
            memory=True,
            max_execution_time=900  # 15 minutes
        )

        # Zero-Day Research Crew
        self.crews["zero_day"] = Crew(
            agents=[
                self.agents["vulnerability_hunter"],
                self.agents["exploit_developer"],
                self.agents["threat_intel"]
            ],
            process=Process.hierarchical,
            manager_llm=self.llm,
            verbose=True,
            memory=True,
            max_execution_time=2400  # 40 minutes
        )

    async def generate_test_suite(self, assessment_request: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive test suite using AI agents"""
        if not self.initialized:
            return self._fallback_test_generation(assessment_request)

        try:
            # Determine assessment scope and crew
            scope = assessment_request.get('assessment_scope', ['comprehensive'])
            crew_name = self._select_appropriate_crew(scope)
            
            if crew_name not in self.crews:
                crew_name = 'comprehensive'

            # Create tasks for the crew
            tasks = self._create_assessment_tasks(assessment_request, crew_name)
            
            # Execute crew assessment
            crew = self.crews[crew_name]
            crew.tasks = tasks
            
            log.info(f"🚀 Starting {crew_name} assessment with CrewAI")
            result = crew.kickoff()
            
            # Process results
            return self._process_crew_results(result, assessment_request)
            
        except Exception as e:
            log.error(f"❌ CrewAI assessment failed: {e}")
            return self._fallback_test_generation(assessment_request)

    def _select_appropriate_crew(self, scope: List[str]) -> str:
        """Select appropriate crew based on assessment scope"""
        if 'quick' in scope or 'fast' in scope:
            return 'quick_scan'
        elif 'compliance' in scope:
            return 'compliance' 
        elif 'zero_day' in scope or 'advanced' in scope:
            return 'zero_day'
        else:
            return 'comprehensive'

    def _create_assessment_tasks(self, request: Dict[str, Any], crew_name: str) -> List[Task]:
        """Create assessment tasks based on request and crew type"""
        target_url = request.get('target_url', '')
        postman_data = request.get('postman_collection', {})
        
        base_context = {
            "target_url": target_url,
            "postman_data": postman_data,
            "assessment_timestamp": datetime.now().isoformat()
        }

        if crew_name == 'comprehensive':
            return self._create_comprehensive_tasks(base_context)
        elif crew_name == 'quick_scan':
            return self._create_quick_scan_tasks(base_context)
        elif crew_name == 'compliance':
            return self._create_compliance_tasks(base_context, request.get('compliance_frameworks', []))
        elif crew_name == 'zero_day':
            return self._create_zero_day_tasks(base_context)
        else:
            return self._create_comprehensive_tasks(base_context)

    def _create_comprehensive_tasks(self, context: Dict[str, Any]) -> List[Task]:
        """Create comprehensive assessment tasks"""
        return [
            Task(
                description=f"""
                Conduct comprehensive API reconnaissance for: {context['target_url']}
                
                Your tasks:
                1. Analyze the API structure and endpoints from Postman collection
                2. Identify potential hidden or undocumented endpoints
                3. Map out authentication mechanisms and access controls
                4. Document API versioning and deprecated endpoints
                5. Identify business logic flows and critical operations
                6. Create a detailed attack surface map
                
                Provide detailed findings with specific recommendations for further testing.
                """,
                expected_output="Detailed reconnaissance report with attack surface mapping and testing recommendations",
                agent=self.agents["reconnaissance"],
                context=context
            ),
            
            Task(
                description=f"""
                Conduct advanced vulnerability discovery based on reconnaissance findings.
                
                Your tasks:
                1. Test for OWASP API Security Top 10 vulnerabilities
                2. Analyze business logic flaws and authorization bypasses  
                3. Test for injection vulnerabilities (SQL, NoSQL, Command, etc.)
                4. Assess rate limiting and resource exhaustion vulnerabilities
                5. Identify data exposure and information leakage issues
                6. Test GraphQL-specific vulnerabilities if applicable
                7. Look for novel attack vectors and zero-day possibilities
                
                Generate specific test cases and payloads for each vulnerability type.
                """,
                expected_output="Comprehensive vulnerability assessment with test cases and exploitation steps",
                agent=self.agents["vulnerability_hunter"],
                context=context
            ),

            Task(
                description="""
                Develop proof-of-concept exploits for identified high-risk vulnerabilities.
                
                Your tasks:
                1. Create safe, educational PoC exploits for critical vulnerabilities
                2. Demonstrate real-world impact and exploitation scenarios
                3. Provide step-by-step exploitation guides
                4. Assess potential for privilege escalation and lateral movement
                5. Evaluate data exposure and business impact
                6. Create remediation-focused exploitation examples
                
                Focus on educational value and clear impact demonstration.
                """,
                expected_output="Educational PoC exploits with impact analysis and remediation guidance",
                agent=self.agents["exploit_developer"],
                context=context
            ),

            Task(
                description="""
                Provide threat intelligence context and risk prioritization.
                
                Your tasks:
                1. Correlate findings with current threat landscape
                2. Identify APT groups or threat actors likely to exploit these vulnerabilities
                3. Analyze attack patterns and TTPs relevant to discovered vulnerabilities
                4. Provide intelligence on exploit availability and active exploitation
                5. Assess likelihood of targeted attacks
                6. Recommend threat-informed defense strategies
                
                Focus on actionable intelligence and strategic recommendations.
                """,
                expected_output="Threat intelligence report with attack likelihood and defense recommendations",
                agent=self.agents["threat_intel"],
                context=context
            ),

            Task(
                description="""
                Conduct comprehensive risk analysis and business impact assessment.
                
                Your tasks:
                1. Quantify risk levels using industry-standard frameworks (CVSS, OWASP Risk Rating)
                2. Assess business impact of identified vulnerabilities
                3. Prioritize remediation based on risk and business criticality
                4. Provide cost-benefit analysis for security improvements
                5. Create executive-level risk summaries
                6. Develop remediation roadmap with timelines and resource requirements
                
                Translate technical findings into business language and actionable recommendations.
                """,
                expected_output="Executive risk assessment with prioritized remediation roadmap",
                agent=self.agents["risk_analyst"],
                context=context
            )
        ]

    def _create_quick_scan_tasks(self, context: Dict[str, Any]) -> List[Task]:
        """Create quick scan tasks for rapid assessment"""
        return [
            Task(
                description=f"""
                Perform rapid vulnerability discovery for: {context['target_url']}
                
                Focus on high-impact, easy-to-exploit vulnerabilities:
                1. Authentication and authorization bypasses
                2. Common injection vulnerabilities  
                3. Data exposure issues
                4. Critical business logic flaws
                5. Known CVE-based vulnerabilities
                
                Prioritize speed while maintaining accuracy.
                """,
                expected_output="Quick vulnerability assessment with high-priority findings",
                agent=self.agents["vulnerability_hunter"],
                context=context
            ),
            
            Task(
                description="""
                Rapidly assess and prioritize discovered vulnerabilities.
                
                Your tasks:
                1. Assign risk ratings to all findings
                2. Identify critical vulnerabilities requiring immediate attention
                3. Provide quick-win remediation recommendations
                4. Assess business impact of top findings
                
                Focus on actionable, high-impact recommendations.
                """,
                expected_output="Risk-prioritized vulnerability list with immediate action items",
                agent=self.agents["risk_analyst"],
                context=context
            )
        ]

    def _create_compliance_tasks(self, context: Dict[str, Any], frameworks: List[str]) -> List[Task]:
        """Create compliance assessment tasks"""
        return [
            Task(
                description=f"""
                Assess API security posture against compliance frameworks: {', '.join(frameworks)}
                
                Your tasks:
                1. Map discovered vulnerabilities to compliance requirements
                2. Identify gaps in security controls
                3. Assess data protection and privacy compliance
                4. Evaluate access controls and audit logging
                5. Check encryption and data transmission security
                6. Provide compliance gap analysis
                
                Focus on regulatory requirements and audit readiness.
                """,
                expected_output="Comprehensive compliance assessment with gap analysis",
                agent=self.agents["compliance"],
                context=context
            )
        ]

    def _create_zero_day_tasks(self, context: Dict[str, Any]) -> List[Task]:
        """Create zero-day research tasks"""
        return [
            Task(
                description="""
                Conduct advanced vulnerability research for potential zero-day discoveries.
                
                Your tasks:
                1. Analyze unusual API behaviors and edge cases
                2. Test novel attack vectors and exploitation techniques
                3. Identify logic flaws that might not be covered by standard tests
                4. Look for implementation-specific vulnerabilities
                5. Research potential for chain exploits
                6. Focus on high-impact, low-detection attack scenarios
                
                Think creatively and look for unique vulnerability patterns.
                """,
                expected_output="Advanced vulnerability research findings with novel attack vectors",
                agent=self.agents["vulnerability_hunter"],
                context=context
            ),
            
            Task(
                description="""
                Develop advanced exploitation techniques for research findings.
                
                Your tasks:
                1. Create sophisticated exploitation chains
                2. Develop bypass techniques for security controls
                3. Research persistence and stealth mechanisms
                4. Analyze potential for widespread impact
                5. Document technical details for responsible disclosure
                
                Focus on advanced techniques and maximum impact demonstration.
                """,
                expected_output="Advanced exploitation research with technical documentation",
                agent=self.agents["exploit_developer"],
                context=context
            )
        ]

    def _process_crew_results(self, results: Any, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process and structure crew assessment results"""
        try:
            # Convert crew results to structured format
            processed_results = {
                "assessment_type": "crewai_autonomous",
                "timestamp": datetime.now().isoformat(),
                "target_info": request.get('target_url', ''),
                "test_cases": [],
                "vulnerabilities": [],
                "recommendations": [],
                "ai_insights": {},
                "metadata": {
                    "crew_used": "comprehensive",
                    "execution_time": 0,
                    "agents_involved": list(self.agents.keys())
                }
            }
            
            # Parse crew results (assuming results is a string or structured data)
            if isinstance(results, str):
                # Extract structured information from text results
                processed_results["ai_insights"]["crew_analysis"] = results
                processed_results["test_cases"] = self._extract_test_cases_from_text(results)
                processed_results["vulnerabilities"] = self._extract_vulnerabilities_from_text(results)
            else:
                # Handle structured results
                processed_results.update(results)
            
            return processed_results
            
        except Exception as e:
            log.error(f"❌ Failed to process crew results: {e}")
            return self._fallback_test_generation(request)

    def _extract_test_cases_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract test cases from crew text output"""
        # Simple extraction - in production, use more sophisticated NLP
        test_cases = []
        
        # Look for common vulnerability patterns
        patterns = {
            "SQL Injection": ["sql injection", "sqli", "union select"],
            "XSS": ["cross-site scripting", "xss", "<script>"],
            "Authentication Bypass": ["auth bypass", "authentication", "unauthorized"],
            "IDOR": ["idor", "insecure direct object", "authorization"],
            "Rate Limiting": ["rate limit", "brute force", "enumeration"]
        }
        
        for vuln_type, keywords in patterns.items():
            if any(keyword in text.lower() for keyword in keywords):
                test_cases.append({
                    "test_name": f"AI-Generated {vuln_type} Test",
                    "vulnerability_type": vuln_type,
                    "method": "POST",
                    "payload": f"/* AI-generated payload for {vuln_type} */",
                    "priority": "high",
                    "ai_generated": True
                })
        
        return test_cases

    def _extract_vulnerabilities_from_text(self, text: str) -> List[Dict[str, Any]]:
        """Extract vulnerability findings from crew text output"""
        vulnerabilities = []
        
        # Simple pattern matching - enhance with proper NLP
        if "critical" in text.lower():
            vulnerabilities.append({
                "severity": "critical",
                "title": "AI-Identified Critical Vulnerability",
                "description": "CrewAI agents identified potential critical security issues",
                "ai_confidence": 0.8,
                "agent_analysis": True
            })
        
        return vulnerabilities

    def _fallback_test_generation(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback test generation when CrewAI is not available"""
        log.info("🔄 Using fallback test generation")
        
        return {
            "assessment_type": "fallback_basic",
            "timestamp": datetime.now().isoformat(),
            "target_info": request.get('target_url', ''),
            "test_cases": [
                {
                    "test_name": "Basic SQL Injection Test",
                    "method": "POST",
                    "payload": "' OR 1=1--",
                    "vulnerability_type": "SQL Injection",
                    "priority": "high"
                },
                {
                    "test_name": "Basic XSS Test", 
                    "method": "GET",
                    "payload": "<script>alert('XSS')</script>",
                    "vulnerability_type": "XSS",
                    "priority": "medium"
                },
                {
                    "test_name": "Authentication Bypass Test",
                    "method": "GET",
                    "headers": {"Authorization": ""},
                    "vulnerability_type": "Authentication Bypass",
                    "priority": "critical"
                }
            ],
            "ai_insights": {
                "note": "Basic fallback test suite - CrewAI unavailable"
            }
        }

    def get_agent_status(self) -> Dict[str, Any]:
        """Get status of all security agents"""
        if not self.initialized:
            return {"status": "not_initialized", "reason": "CrewAI not available"}
            
        return {
            "status": "active",
            "agents": {name: {"role": agent.role, "goal": agent.goal} 
                      for name, agent in self.agents.items()},
            "crews": list(self.crews.keys()),
            "llm_model": str(type(self.llm).__name__) if self.llm else "none"
        }
