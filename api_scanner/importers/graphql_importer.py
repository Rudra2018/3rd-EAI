import aiohttp
from typing import Optional, Dict, Any

INTROSPECTION_QUERY = {
  "query": """
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      subscriptionType { name }
      types {
        kind name
        fields(includeDeprecated:true){
          name
          args { name type { kind name } }
        }
      }
      directives { name }
    }
  }"""
}

async def parse_graphql(endpoint: str) -> Optional[Dict[str, Any]]:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(endpoint, json=INTROSPECTION_QUERY, timeout=20) as r:
                if r.status != 200:
                    return None
                data = await r.json()
                return data
    except Exception:
        return None

