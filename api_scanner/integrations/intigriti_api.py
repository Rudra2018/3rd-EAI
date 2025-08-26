import os, json, logging, requests
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)
UA = os.getenv("SCRAPER_UA", "Mozilla/5.0 (compatible; Rudra-Scanner/1.0)")
SCRAPE = os.getenv("PUBLIC_HTML_SCRAPE_OK", "false").lower() in ("1","true","yes")

class IntigritiClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.base = "https://www.intigriti.com/researchers/bug-bounty-programs"
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": UA})

    @classmethod
    def from_env(cls):
        return cls()

    def list_programs(self) -> List[Dict[str, Any]]:
        env_json = os.getenv("INTI_PROGRAMS_JSON")
        if env_json:
            try:
                return json.loads(env_json)
            except Exception:
                pass
        if not SCRAPE:
            log.warning("HTML scraping disabled. Provide INTI_PROGRAMS_JSON to seed.")
            return []

        try:
            r = self.s.get(self.base, timeout=30)
            if r.status_code != 200:
                return []
            soup = BeautifulSoup(r.text, "html.parser")
            cards = soup.select("a[href*='/public/']")
            progs = []
            seen = set()
            for a in cards:
                href = a.get("href","")
                if not href: continue
                if not href.startswith("http"):
                    href = "https://www.intigriti.com" + href
                if href in seen: continue
                seen.add(href)
                name = (a.get_text() or "").strip() or href.rsplit("/",1)[-1]
                progs.append({
                    "platform": "intigriti",
                    "slug": name.lower().replace(" ", "-"),
                    "policy": href,
                    "targets": []
                })
            return progs
        except Exception as e:
            log.warning(f"Intigriti scrape failed: {e}")
            return []

