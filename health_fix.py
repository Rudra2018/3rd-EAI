@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "version": "5.0.0",
        "timestamp": datetime.now().isoformat(),
        "components": {
            "postman_parser": True,
            "ai_test_generator": True,
            "ai_coordinator": True,
            "bug_bounty_scanner": True
        },
        "features": [
            "ai_powered_analysis",
            "comprehensive_testing",
            "postman_integration",
            "bug_bounty_intelligence"
        ]
    }
