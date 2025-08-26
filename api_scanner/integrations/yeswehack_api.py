import os, time, re, json, logging, requests
from typing import List, Dict, Any, Optional
from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

UA = os.getenv("SCRAPER_UA", "Mozilla/5.0 (compatible; Rudra-Scanner/1.0)")
SCRAPE = os.getenv("PUBLIC_HTML_SCRAPE_OK", "false").lower() in ("1","true","yes")

class YesWeHackClient:
    def __init__(self, session: Optional[requests.Session] = None):
        self.base = "https://yeswehack.com/programs"
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": UA})

    @classmethod
    def from_env(cls):
        return cls()

    def list_programs(self) -> List[Dict[str, Any]]:
        """Best-effort public list. Prefer YWH API if you have it; otherwise gated scrape."""
        env_json = os.getenv("YWH_PROGRAMS_JSON")
        if env_json:
            try:
                return json.loads(env_json)
            except Exception:
                pass

        if not SCRAPE:
            log.warning("HTML scraping disabled (PUBLIC_HTML_SCRAPE_OK=false). Set to true to allow.")
            return []

        progs = []
        url = self.base
        try:
            r = self.s.get(url, timeout=30)
            if r.status_code != 200:
                return []
            soup = BeautifulSoup(r.text, "html.parser")
            cards = soup.select("a[href*='/programs/']")
            seen = set()
            for a in cards:
                href = a.get("href","")
                if not href or href in seen: continue
                if not href.startswith("http"):
                    href = "https://yeswehack.com" + href
                seen.add(href)
                name = (a.get_text() or "").strip() or href.rsplit("/",1)[-1]
                progs.append({
                    "platform": "yeswehack",
                    "slug": name.lower().replace(" ", "-"),
                    "policy": href,
                    "targets": []  # scope fetch needs per-program page; left empty for safety
                })
            return progs
        except Exception as e:
            log.warning(f"YWH scrape failed: {e}")
            return []

